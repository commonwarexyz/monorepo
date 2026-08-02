//! A reusable deterministic Multimmit cluster over the simulated network.
//!
//! The harness launches complete production engines (batcher, voter, resolver, storage) for one
//! committee, with per-node crash/restart, link partitions, and finality assertions. It
//! runs only under the deterministic runtime; wall-clock schedules replay exactly per seed.

use crate::{
    multimmit::{
        config::{LeaderSchedule, Limits},
        engine::{Config as EngineConfig, Engine, Running},
        machine::{Inspection, Profile, Role, Tuning},
        mocks::{Committee, MockApplication, NoopReporter},
    },
    types::{Participant, View, ViewDelta},
};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::Variant, ed25519,
    ed25519::PrivateKey as Ed25519PrivateKey, sha256::Digest as Sha256Digest,
};
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
    Clock as _, Handle, Quota, Spawner, Supervisor as _, deterministic,
    mocks::{DelayedSyncContext, PendingSyncs, release_pending_syncs},
};
use commonware_utils::NZUsize;
#[cfg(test)]
use commonware_utils::sync::Mutex;
use rand_core::CryptoRng;
#[cfg(test)]
use std::{num::NonZeroU64, sync::Arc, time::SystemTime};
use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::{Duration, Instant},
};

const LABELS: [[&str; 4]; 16] = [
    ["n0a", "n0b", "n0c", "n0d"],
    ["n1a", "n1b", "n1c", "n1d"],
    ["n2a", "n2b", "n2c", "n2d"],
    ["n3a", "n3b", "n3c", "n3d"],
    ["n4a", "n4b", "n4c", "n4d"],
    ["n5a", "n5b", "n5c", "n5d"],
    ["n6a", "n6b", "n6c", "n6d"],
    ["n7a", "n7b", "n7c", "n7d"],
    ["n8a", "n8b", "n8c", "n8d"],
    ["n9a", "n9b", "n9c", "n9d"],
    ["n10a", "n10b", "n10c", "n10d"],
    ["n11a", "n11b", "n11c", "n11d"],
    ["n12a", "n12b", "n12c", "n12d"],
    ["n13a", "n13b", "n13c", "n13d"],
    ["n14a", "n14b", "n14c", "n14d"],
    ["n15a", "n15b", "n15c", "n15d"],
];

type MockEngineConfig<V> = EngineConfig<
    Sha256,
    ed25519::PublicKey,
    V,
    MockApplication,
    MockApplication,
    NoopReporter<V, Sha256Digest>,
    Sequential,
    Control<ed25519::PublicKey, deterministic::Context>,
>;

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
    /// Per-peer, per-plane message rate, or unlimited when absent.
    ///
    /// A deployment rate-limits every plane. Multimmit exits a view as soon as its V-QC forms, so
    /// its message rate is set by the network rather than by a timer, and a quota sized for one
    /// view per second starves view exits while the producer chains keep running.
    pub quota: Option<Quota>,
    /// One-way link latency, or two milliseconds when absent.
    pub latency: Option<Duration>,
    /// Uniform per-message link jitter, or none when absent.
    ///
    /// Jitter desynchronizes the replicas' view and ordering schedules, which is what surfaces
    /// interleavings a uniform-latency cluster can never produce.
    pub jitter: Option<Duration>,
    /// Empty-build retry interval, or 100 milliseconds when absent.
    pub production: Option<Duration>,
    /// Retained views below the current one, or sixteen when absent.
    pub view_retention: Option<ViewDelta>,
}

/// One deterministic cluster of complete Multimmit engines.
pub struct Cluster<V: Variant> {
    options: ClusterOptions,
    producers: Vec<Participant>,
    context: deterministic::Context,
    oracle: Oracle<ed25519::PublicKey, deterministic::Context>,
    identities: Vec<ed25519::PublicKey>,
    apps: Vec<MockApplication>,
    engines: Vec<Option<RunningEngine<V>>>,
    finality_history: Vec<FinalityHistory>,
    #[cfg(test)]
    task_prefixes: Vec<Option<String>>,
    #[cfg(test)]
    blocked_consensus_recipients: Vec<Arc<Mutex<Vec<ed25519::PublicKey>>>>,
    #[cfg(test)]
    blocked_certificate_recipients: Vec<Arc<Mutex<Vec<ed25519::PublicKey>>>>,
    #[cfg(test)]
    checkpoint_interval: Option<NonZeroU64>,
    generations: Vec<usize>,
    production_policy: ProductionPolicy,
    storage_sync_interval: Option<Duration>,
}

struct RunningEngine<V: Variant> {
    engine: Running<V, Sha256Digest>,
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
        self.engine.join().await;
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
    generation: u64,
    finality_floor: View,
}

impl FinalityHistory {
    const fn new() -> Self {
        Self {
            generation: 0,
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
            use commonware_cryptography::Signer as _;
            identities.push(
                Ed25519PrivateKey::from_seed(options.seed ^ 0xdead_beef ^ u64::from(extra))
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
            apps: Vec::new(),
            engines: Vec::new(),
            finality_history: Vec::new(),
            #[cfg(test)]
            task_prefixes: Vec::new(),
            #[cfg(test)]
            blocked_consensus_recipients: Vec::new(),
            #[cfg(test)]
            blocked_certificate_recipients: Vec::new(),
            #[cfg(test)]
            checkpoint_interval: None,
            generations: Vec::new(),
            production_policy: ProductionPolicy::Paused,
            storage_sync_interval: None,
        };
        cluster.heal().await;
        cluster
    }

    fn committee(options: &ClusterOptions, producers: &[Participant]) -> Committee<V> {
        let mut committee = Committee::new_with_namespace_and_producers(
            options.seed,
            super::NAMESPACE,
            options.n,
            producers.to_vec(),
            Limits::new(2, 1).unwrap(),
        );
        if let Some(leaders) = &options.leaders {
            committee = committee.with_leaders(leaders.clone());
        }
        committee
    }

    /// Returns every identity in committee order, followed by any extras.
    pub fn identities(&self) -> Vec<ed25519::PublicKey> {
        self.identities.clone()
    }

    /// Sets the shared checkpoint cadence before any engine starts.
    #[cfg(test)]
    pub fn set_checkpoint_interval(&mut self, checkpoint_interval: NonZeroU64) {
        assert!(
            self.generations.iter().all(|generation| *generation == 0),
            "checkpoint interval must be set before any engine starts"
        );
        self.checkpoint_interval = Some(checkpoint_interval);
    }

    /// Delays started durability syncs by releasing them at a fixed interval.
    pub fn set_storage_sync_interval(&mut self, interval: Duration) {
        assert!(
            !interval.is_zero(),
            "storage sync interval must be non-zero"
        );
        assert!(
            self.generations.iter().all(|generation| *generation == 0),
            "storage sync interval must be set before any engine starts"
        );
        self.storage_sync_interval = Some(interval);
    }

    /// Starts one committee engine without waiting for readiness.
    pub async fn start_one(&mut self, index: usize) {
        while self.apps.len() <= index {
            let application = self.new_application("");
            self.apps.push(application);
            self.engines.push(None);
            self.finality_history.push(FinalityHistory::new());
            #[cfg(test)]
            self.task_prefixes.push(None);
            #[cfg(test)]
            self.blocked_consensus_recipients
                .push(Arc::new(Mutex::new(Vec::new())));
            #[cfg(test)]
            self.blocked_certificate_recipients
                .push(Arc::new(Mutex::new(Vec::new())));
            self.generations.push(0);
        }
        self.launch(index).await;
    }

    /// Waits for every listed engine to become ready.
    pub async fn await_ready(&mut self, nodes: &[usize]) {
        for &index in nodes {
            let ready = self.engines[index]
                .as_mut()
                .expect("engine launched")
                .engine
                .ready()
                .await;
            assert!(ready, "engine {index} becomes ready");
        }
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
        &self.apps[index]
    }

    /// Returns the simulated-network oracle for custom link and bandwidth schedules.
    pub const fn oracle(&self) -> &Oracle<ed25519::PublicKey, deterministic::Context> {
        &self.oracle
    }

    /// Returns the per-plane quota this cluster registers with.
    fn quota(&self) -> Quota {
        self.options.quota.unwrap_or(QUOTA)
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
            .register(channel, self.quota())
            .await
            .unwrap()
    }

    fn profile(
        options: &ClusterOptions,
        committee: &Committee<V>,
        role: Role,
    ) -> Profile<Sha256, V> {
        Profile::new(
            committee.config.clone(),
            role,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: options.production.unwrap_or(Duration::from_millis(100)),
                // Deterministic scenarios run hundreds of views, so keep the retained window
                // small enough that retirement is exercised without holding every view.
                view_retention: options.view_retention.unwrap_or(ViewDelta::new(16)),
                ..Tuning::default()
            },
        )
        .unwrap()
    }

    /// Starts every committee engine fresh.
    pub async fn start_all(&mut self) {
        for index in 0..self.options.n as usize {
            let application = self.new_application("");
            self.apps.push(application);
            self.engines.push(None);
            self.finality_history.push(FinalityHistory::new());
            #[cfg(test)]
            self.task_prefixes.push(None);
            #[cfg(test)]
            self.blocked_consensus_recipients
                .push(Arc::new(Mutex::new(Vec::new())));
            #[cfg(test)]
            self.blocked_certificate_recipients
                .push(Arc::new(Mutex::new(Vec::new())));
            self.generations.push(0);
            self.launch(index).await;
        }
        for index in 0..self.options.n as usize {
            let ready = self.engines[index]
                .as_mut()
                .expect("engine launched")
                .engine
                .ready()
                .await;
            assert!(ready, "engine {index} becomes ready");
        }
    }

    /// Launches (or relaunches) one engine over its own registered planes.
    pub async fn launch(&mut self, index: usize) {
        // Re-registration replaces the previous instance's mailboxes, so a restarted node keeps
        // receiving on the same four planes its peers already target.
        let me = self.identities[index].clone();
        let mut planes = Vec::new();
        for channel in 0..4u64 {
            planes.push(
                self.oracle
                    .control(me.clone())
                    .register(channel, self.quota())
                    .await
                    .unwrap(),
            );
        }
        let mut planes = planes.into_iter();
        let (data, consensus, certificates, resolver) = (
            planes.next().unwrap(),
            planes.next().unwrap(),
            planes.next().unwrap(),
            planes.next().unwrap(),
        );
        #[cfg(test)]
        let consensus = (
            BlockingSender {
                inner: consensus.0,
                me: me.clone(),
                identities: self.identities.clone(),
                blocked: Arc::clone(&self.blocked_consensus_recipients[index]),
            },
            consensus.1,
        );
        #[cfg(test)]
        let certificates = (
            BlockingSender {
                inner: certificates.0,
                me: me.clone(),
                identities: self.identities.clone(),
                blocked: Arc::clone(&self.blocked_certificate_recipients[index]),
            },
            certificates.1,
        );
        self.launch_with(index, index, None, data, consensus, certificates, resolver)
            .await;
    }

    /// Launches one engine over caller-supplied plane transports.
    ///
    /// `signer` selects whose key material the engine uses, which a twin half sets to another
    /// participant. `slot` names the storage and application slot, so two halves of one
    /// participant keep entirely separate durable state. `label` distinguishes a half in metrics
    /// and traces.
    #[allow(clippy::too_many_arguments)]
    pub async fn launch_with<Sd, Sg, Rc, Sc, Sr, Rr>(
        &mut self,
        slot: usize,
        signer: usize,
        label: Option<&'static str>,
        data: (Sd, Rc),
        consensus: (Sg, Rc),
        certificates: (Sc, Rc),
        resolver: (Sr, Rr),
    ) where
        Sd: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Sg: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Rc: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        Sc: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Sr: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Rr: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let committee = Self::committee(&self.options, &self.producers);
        // Both halves of a twin share the signing participant's one network identity, which is
        // what makes honest nodes attribute them to a single committee weight.
        let me = self.identities[signer].clone();
        let role = Role::Validator(Participant::new(signer as u32));
        let profile = Self::profile(&self.options, &committee, role);
        let generation = self.generations[slot];
        self.generations[slot] += 1;
        let label = label.unwrap_or(LABELS[slot][generation.min(3)]);
        let index = slot;

        let application = self.apps[index].clone();
        let engine_context = self.context.child(label);
        #[cfg(test)]
        {
            self.task_prefixes[index] = Some(engine_context.name().label);
        }
        let config = || EngineConfig {
            scheme: committee.signers[signer].clone(),
            automaton: application.clone(),
            relay: application.clone(),
            reporter: NoopReporter::default(),
            strategy: Sequential,
            blocker: self.oracle.control(me.clone()),
            profile: profile.clone(),
            partition_prefix: format!("cluster-{}-{index}", self.options.seed),
            mailbox_size: NonZeroUsize::new(128).unwrap(),
        };
        let mut storage_sync_task: Option<Handle<()>> = None;
        let running = if let Some(interval) = self.storage_sync_interval {
            let pending_syncs = PendingSyncs::completion_delayed();
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
            self.start_engine(
                engine_context,
                config(),
                data,
                consensus,
                certificates,
                resolver,
            )
            .await
        } else {
            self.start_engine(
                engine_context,
                config(),
                data,
                consensus,
                certificates,
                resolver,
            )
            .await
        };
        self.engines[index] = Some(RunningEngine {
            engine: running,
            storage_sync_task,
        });
    }

    async fn start_engine<E, Sd, Sg, Rc, Sc, Sr, Rr>(
        &self,
        context: E,
        config: MockEngineConfig<V>,
        data: (Sd, Rc),
        consensus: (Sg, Rc),
        certificates: (Sc, Rc),
        resolver: (Sr, Rr),
    ) -> Running<V, Sha256Digest>
    where
        E: commonware_runtime::Clock
            + CryptoRng
            + Spawner
            + commonware_runtime::Storage
            + commonware_runtime::Metrics
            + commonware_runtime::BufferPooler,
        Sd: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Sg: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Rc: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
        Sc: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Sr: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
        Rr: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    {
        let engine = Engine::new(context, config);
        #[cfg(test)]
        let engine = match self.checkpoint_interval {
            Some(checkpoint_interval) => engine.with_checkpoint_interval(checkpoint_interval),
            None => engine,
        };

        Box::pin(engine.start(data, consensus, certificates, resolver))
            .await
            .expect("engine starts")
    }

    /// Reserves a storage and application slot for one extra engine, such as a twin half.
    ///
    /// The slot owns separate durable state, application instance, and scheduling. `salt` makes
    /// the application build a different body for the same chain position, which forces a
    /// key-sharing twin to equivocate as a producer.
    pub fn reserve_slot(&mut self, salt: &'static str) -> usize {
        let slot = self.apps.len();
        let application = self.new_application(salt);
        self.apps.push(application);
        self.engines.push(None);
        self.finality_history.push(FinalityHistory::new());
        #[cfg(test)]
        self.task_prefixes.push(None);
        #[cfg(test)]
        self.blocked_consensus_recipients
            .push(Arc::new(Mutex::new(Vec::new())));
        #[cfg(test)]
        self.blocked_certificate_recipients
            .push(Arc::new(Mutex::new(Vec::new())));
        self.generations.push(0);
        slot
    }

    fn new_application(&self, salt: &'static str) -> MockApplication {
        let application = MockApplication::with_salt(salt);
        application.pause_building();
        Self::apply_production_policy(&application, self.production_policy);
        application
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
        for application in &self.apps {
            Self::apply_production_policy(application, self.production_policy);
        }
    }

    /// Crashes one engine uncleanly, leaving its durable partitions intact.
    pub async fn crash(&mut self, index: usize) {
        self.observe_running_finality().await;
        let engine = self.engines[index].take().expect("engine is running");

        #[cfg(test)]
        let task_prefix = self.task_prefixes[index]
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
        assert!(self.engines[index].is_none(), "crash before restarting");
        self.launch(index).await;
        let ready = self.engines[index]
            .as_mut()
            .expect("engine launched")
            .engine
            .ready()
            .await;
        assert!(ready, "engine {index} becomes ready after restart");
        self.observe_running_finality().await;
    }

    /// Applies full connectivity between every pair of identities.
    pub async fn heal(&mut self) {
        self.observe_running_finality().await;
        link_all_with(
            &self.oracle,
            &self.identities,
            self.options.latency.unwrap_or(DEFAULT_LATENCY),
            self.options.jitter.unwrap_or(Duration::ZERO),
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
        let identities = self.identities.clone();
        let node = identities[index].clone();
        let link = Link {
            latency: self.options.latency.unwrap_or(DEFAULT_LATENCY),
            jitter: self.options.jitter.unwrap_or(Duration::ZERO),
            success_rate,
        };
        for peer in identities {
            if peer == node {
                continue;
            }
            self.replace_link(node.clone(), peer.clone(), link.clone())
                .await;
            self.replace_link(peer, node.clone(), link.clone()).await;
        }
        self.observe_running_finality().await;
    }

    /// Applies one delivery rate to a single directed link.
    pub async fn set_directed_success_rate(&mut self, from: usize, to: usize, success_rate: f64) {
        let link = Link {
            latency: self.options.latency.unwrap_or(DEFAULT_LATENCY),
            jitter: self.options.jitter.unwrap_or(Duration::ZERO),
            success_rate,
        };
        self.replace_link(
            self.identities[from].clone(),
            self.identities[to].clone(),
            link,
        )
        .await;
    }

    /// Drops certificate-plane sends from one engine to one identity.
    #[cfg(test)]
    pub fn block_certificates(&self, from: usize, to: usize) {
        let recipient = self.identities[to].clone();
        let mut blocked = self.blocked_certificate_recipients[from].lock();
        if !blocked.contains(&recipient) {
            blocked.push(recipient);
        }
    }

    /// Drops consensus-plane sends from one engine to one identity.
    #[cfg(test)]
    pub fn block_consensus(&self, from: usize, to: usize) {
        let recipient = self.identities[to].clone();
        let mut blocked = self.blocked_consensus_recipients[from].lock();
        if !blocked.contains(&recipient) {
            blocked.push(recipient);
        }
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
            self.apps[index].pause_building();
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
            success_rate,
        };
        let identities = self.identities.clone();
        for from in &identities {
            for to in &identities {
                if from == to {
                    continue;
                }
                let _ = self.oracle.remove_link(from.clone(), to.clone()).await;
                self.oracle
                    .add_link(from.clone(), to.clone(), link.clone())
                    .await
                    .expect("network conditions are valid");
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
            for application in &self.apps {
                application.permit_builds(1);
            }
        }
    }

    /// Reads one running node's machine projection.
    pub async fn inspect(&self, index: usize) -> Option<Inspection<Sha256Digest>> {
        match &self.engines[index] {
            Some(engine) => engine.engine.inspect().await,
            None => None,
        }
    }

    /// Reads one checkpoint retained by a running engine's volatile resolver.
    pub async fn serve(
        &self,
        index: usize,
        view: View,
    ) -> Option<crate::multimmit::actors::resolver::Served<V, Sha256Digest>> {
        match &self.engines[index] {
            Some(engine) => engine.engine.serve(view).await,
            None => None,
        }
    }

    /// Returns the durable safety-journal sections retained for one engine.
    #[cfg(test)]
    pub async fn journal_sections(&self, index: usize) -> Vec<u64> {
        let partition = format!(
            "cluster-{}-{index}-multimmit-machine-journal",
            self.options.seed
        );
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
        let partition = format!(
            "cluster-{}-{index}-multimmit-machine-checkpoints",
            self.options.seed
        );
        self.context
            .scan(&partition)
            .await
            .unwrap_or_else(|error| panic!("scan engine {index} checkpoints: {error}"))
            .len()
    }

    /// Returns every peer pair recorded by the simulated network's real blocker.
    #[cfg(test)]
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
            self.finality_history[index].observe(index, &inspection);
        }
    }

    async fn observe_running_finality(&mut self) {
        let nodes = self
            .engines
            .iter()
            .enumerate()
            .filter_map(|(index, engine)| engine.as_ref().map(|_| index))
            .collect::<Vec<_>>();
        self.observe_finality(&nodes).await;
    }

    /// Waits until every listed node has durably produced at least `blocks` transaction blocks.
    ///
    /// This lets topology tests stop synthetic work before waiting for consensus, keeping their
    /// message volume bounded without relying on a wall-clock delay.
    pub async fn wait_produced(&mut self, nodes: &[usize], blocks: u64, rounds: usize) {
        self.wait_produced_inner(nodes, blocks, rounds).await;
    }

    /// Waits for production and returns engine time without finality-observation time.
    pub async fn measure_wait_produced(
        &mut self,
        nodes: &[usize],
        blocks: u64,
        rounds: usize,
    ) -> Duration {
        self.wait_produced_inner(nodes, blocks, rounds).await
    }

    async fn wait_produced_inner(
        &mut self,
        nodes: &[usize],
        blocks: u64,
        rounds: usize,
    ) -> Duration {
        let mut elapsed = Duration::ZERO;
        for _ in 0..rounds {
            let started = Instant::now();
            self.refresh();
            self.context.sleep(Duration::from_millis(100)).await;
            let mut done = true;
            for &index in nodes {
                let Some(inspection) = self.inspect(index).await else {
                    panic!("engine {index} failed");
                };
                if inspection.produced_blocks() < blocks {
                    done = false;
                    break;
                }
            }
            elapsed += started.elapsed();
            self.observe_finality(nodes).await;
            if done {
                return elapsed;
            }
        }
        panic!("nodes {nodes:?} did not produce {blocks} blocks in time");
    }

    /// Waits until every listed node finalizes `height` on every listed chain.
    pub async fn wait_finalized(
        &mut self,
        nodes: &[usize],
        chains: &[u32],
        height: u64,
        rounds: usize,
    ) {
        self.wait_finalized_inner(nodes, chains, height, rounds)
            .await;
    }

    /// Waits for finality and returns engine time without observation time.
    pub async fn measure_wait_finalized(
        &mut self,
        nodes: &[usize],
        chains: &[u32],
        height: u64,
        rounds: usize,
    ) -> Duration {
        self.wait_finalized_inner(nodes, chains, height, rounds)
            .await
    }

    async fn wait_finalized_inner(
        &mut self,
        nodes: &[usize],
        chains: &[u32],
        height: u64,
        rounds: usize,
    ) -> Duration {
        let mut elapsed = Duration::ZERO;
        for _ in 0..rounds {
            let started = Instant::now();
            self.refresh();
            self.context.sleep(Duration::from_millis(100)).await;
            let mut done = true;
            for &index in nodes {
                let Some(inspection) = self.inspect(index).await else {
                    panic!("engine {index} failed");
                };
                for &chain in chains {
                    let progress = inspection
                        .chain_progress()
                        .get(chain as usize)
                        .unwrap_or_else(|| panic!("engine {index} does not track chain {chain}"));
                    if progress.finalized().get() < height {
                        done = false;
                        break;
                    }
                }
                if !done {
                    break;
                }
            }
            elapsed += started.elapsed();
            self.observe_finality(nodes).await;
            if done {
                return elapsed;
            }
        }
        panic!(
            "nodes {nodes:?} did not finalize height {height} on every chain in {chains:?} in time"
        );
    }

    /// Waits until every listed node reaches `view` and observes finality while it advances.
    pub async fn wait_view(&mut self, nodes: &[usize], view: View, rounds: usize) {
        self.wait_view_inner(nodes, view, rounds).await;
    }

    /// Waits for a view and returns engine time plus the terminal per-node views.
    pub async fn measure_wait_view(
        &mut self,
        nodes: &[usize],
        view: View,
        rounds: usize,
    ) -> (Duration, Vec<u64>) {
        self.wait_view_inner(nodes, view, rounds).await
    }

    async fn wait_view_inner(
        &mut self,
        nodes: &[usize],
        view: View,
        rounds: usize,
    ) -> (Duration, Vec<u64>) {
        let mut elapsed = Duration::ZERO;
        for _ in 0..rounds {
            let started = Instant::now();
            self.refresh();
            self.context.sleep(Duration::from_millis(10)).await;
            let mut done = true;
            let mut views = Vec::with_capacity(nodes.len());
            for &index in nodes {
                let Some(inspection) = self.inspect(index).await else {
                    panic!("engine {index} failed");
                };
                let current = inspection.view();
                views.push(current.get());
                if current < view {
                    done = false;
                }
            }
            elapsed += started.elapsed();
            self.observe_finality(nodes).await;
            if done {
                return (elapsed, views);
            }
        }
        panic!("nodes {nodes:?} did not reach view {view} in time");
    }

    /// Observes monotonic local finality without granting interval-production credits.
    pub async fn observe_finality_progress(&mut self, nodes: &[usize], rounds: usize) {
        for _ in 0..rounds {
            self.context.sleep(Duration::from_millis(100)).await;
            self.observe_finality(nodes).await;
        }
    }
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
        success_rate: 1.0,
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

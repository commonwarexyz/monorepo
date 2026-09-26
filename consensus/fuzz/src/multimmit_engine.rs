//! Byte-driven crash, recovery, and network scheduling for production Multimmit engines.

use commonware_consensus::{
    Epochable as _, Heightable as _,
    multimmit::{
        Artifact, FinalityFact, FinalityId, Inspection,
        mocks::{
            RecordingReporter,
            cluster::{Cluster, ClusterOptions, Launch, LaunchSpec},
        },
        test_utils::{ResourceLimits, inspection_cursor, inspection_generation, resource_limits},
        types::{Activity, BlockRef, ChainId, PathLimits},
    },
    types::{Attributable as _, Epoch, ViewDelta},
};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::Variant, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Link;
use commonware_runtime::{Clock as _, Runner as _, deterministic};
use commonware_utils::{FuzzRng, probability};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

const NODES: usize = 6;
const SEED_BYTES: usize = std::mem::size_of::<u64>();
const MAX_ACTIONS: usize = 16;
const MAX_INPUT_BYTES: usize = MAX_ACTIONS;
const ACTION_KINDS: usize = 6;
const ACTION_TICK: Duration = Duration::from_millis(50);
const RELOAD_DELAY: Duration = Duration::from_millis(20);
const FINAL_TICKS: usize = 400;
const RUNNER_TIMEOUT: Duration = Duration::from_secs(60);

/// Runs one bounded production-engine campaign for a BLS12-381 signature variant.
pub fn fuzz<V: Variant>(input: &[u8]) {
    let input = bounded_input(input);
    let seed = seed(input);
    let input = input.to_vec();
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_rng(FuzzRng::new(input.clone()))
            .with_timeout(Some(RUNNER_TIMEOUT)),
    );

    runner.start(|context| async move {
        let mut harness = Harness::<V>::new(context, seed).await;
        harness.start_all().await;

        let actions = input.as_slice();
        let checkpoint = actions.len().div_ceil(2);
        for action in &actions[..checkpoint] {
            harness.apply(*action).await;
        }

        harness.reopen_all().await;
        for action in &actions[checkpoint..] {
            harness.apply(*action).await;
        }

        harness.finish().await;
        harness.stop_all().await;
    });
}

fn bounded_input(input: &[u8]) -> &[u8] {
    &input[..input.len().min(MAX_INPUT_BYTES)]
}

fn seed(input: &[u8]) -> u64 {
    let mut bytes = [0u8; SEED_BYTES];
    let len = input.len().min(bytes.len());
    bytes[..len].copy_from_slice(&input[..len]);
    u64::from_be_bytes(bytes)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ActionKind {
    Reload,
    InterruptRecovery,
    Disconnect,
    Degrade,
    Heal,
    Tick,
}

fn decode_action(byte: u8) -> (usize, ActionKind) {
    let byte = usize::from(byte);
    let node = byte % NODES;
    let kind = match (byte / NODES) % ACTION_KINDS {
        0 => ActionKind::Reload,
        1 => ActionKind::Disconnect,
        2 => ActionKind::Degrade,
        3 => ActionKind::Tick,
        4 => ActionKind::Heal,
        5 => ActionKind::InterruptRecovery,
        _ => unreachable!("action kind is reduced modulo {ACTION_KINDS}"),
    };
    (node, kind)
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum NetworkState {
    #[default]
    Healthy,
    Degraded,
    Disconnected,
}

impl NetworkState {
    const fn link(self) -> Link {
        match self {
            Self::Healthy => Link {
                latency: Duration::from_millis(2),
                jitter: Duration::from_millis(5),
                success_rate: probability!(1.0),
            },
            Self::Degraded => Link {
                latency: Duration::from_millis(25),
                jitter: Duration::from_millis(5),
                success_rate: probability!(0.5),
            },
            Self::Disconnected => Link {
                latency: Duration::from_millis(2),
                jitter: Duration::from_millis(5),
                success_rate: probability!(0.0),
            },
        }
    }
}

fn signer_tally_is_valid(
    signers: impl IntoIterator<Item = u32>,
    participants: usize,
    threshold: usize,
) -> bool {
    let mut unique = BTreeSet::new();
    for signer in signers {
        if signer as usize >= participants || !unique.insert(signer) {
            return false;
        }
    }
    unique.len() >= threshold
}

struct Harness<V: Variant> {
    context: deterministic::Context,
    cluster: Cluster<V>,
    reporters: Vec<RecordingReporter<V, Sha256Digest>>,
    running: [bool; NODES],
    state: Invariants,
    resources: ResourceLimits,
    network: [NetworkState; NODES],
}

impl<V: Variant> Harness<V> {
    async fn new(context: deterministic::Context, seed: u64) -> Self {
        let mut cluster = Cluster::new(
            &context,
            ClusterOptions {
                view_retention: ViewDelta::new(8),
                limits: PathLimits::new(2, 1).expect("fuzz limits are valid"),
                ..ClusterOptions::new(seed, NODES as u32)
            },
        )
        .await;
        cluster.produce();
        for node in 0..NODES {
            assert_eq!(
                cluster.reserve_slot(""),
                node,
                "slots stay in participant order"
            );
        }
        let committee = cluster.fixture();
        let resources = resource_limits::<Sha256, V>(committee.config.clone(), cluster.tuning())
            .expect("fuzz tuning is valid");
        let state = Invariants::new(committee.config.epoch(), committee.codec());

        Self {
            context,
            cluster,
            reporters: (0..NODES).map(|_| RecordingReporter::default()).collect(),
            running: [false; NODES],
            state,
            resources,
            network: [NetworkState::Healthy; NODES],
        }
    }

    async fn start_all(&mut self) {
        for node in 0..NODES {
            self.start(node, false).await;
        }
        self.observe().await;
    }

    /// Starts `node`; with `interrupt`, first abandons one recovery at its custody fence.
    ///
    /// Returns whether a recovery was interrupted.
    async fn start(&mut self, node: usize, interrupt: bool) -> bool {
        assert!(!self.running[node], "start requires a stopped engine");
        let spec = LaunchSpec::new(node).reporter(self.reporters[node].clone());
        if !interrupt {
            self.cluster.launch(spec).await;
            self.cluster.await_ready(&[node]).await;
            self.running[node] = true;
            return false;
        }

        let mut gate = self
            .cluster
            .app(node)
            .gate_verifications(1)
            .pop()
            .expect("one recovery custody gate");
        let reports = self.reporters[node].len();
        let proposed = self.cluster.app(node).log().lock().proposed;
        let fenced = Cell::new(false);
        let context = &self.context;
        let interrupt = async {
            gate.wait_started().await;
            fenced.set(true);
            context.sleep(RELOAD_DELAY).await;
        };
        match self.cluster.launch_racing(spec, interrupt).await {
            Launch::Started => {
                assert!(!fenced.get(), "recovery crossed unresolved custody");
                self.cluster.await_ready(&[node]).await;
                self.running[node] = true;
                false
            }
            Launch::Interrupted(()) => {
                assert_eq!(self.reporters[node].len(), reports);
                assert_eq!(self.cluster.app(node).log().lock().proposed, proposed);
                gate.wait_cancelled().await;
                Box::pin(self.start(node, false)).await;
                true
            }
        }
    }

    /// Crashes `node` once no persistence barrier is pending.
    ///
    /// The cross-restart invariants compare recovered state against every event the engine
    /// applied before the crash, so each staged barrier must be durable first. A non-urgent
    /// (reconstructible) barrier syncs only on a later demand, which a partitioned node with
    /// nothing left to do never makes, so the harness demands it.
    async fn stop(&mut self, node: usize) {
        assert!(self.running[node], "stop requires a running engine");
        loop {
            let inspection = self
                .cluster
                .inspect(node)
                .await
                .unwrap_or_else(|| panic!("engine {node} stopped unexpectedly"));
            let persistence_pending = inspection.persistence_pending();
            self.state
                .observe_inspection(node, &inspection, self.resources);
            if !persistence_pending {
                break;
            }
            assert!(
                self.cluster.flush(node),
                "engine {node} accepts flush requests"
            );
        }
        self.cluster.crash(node).await;
        self.running[node] = false;
    }

    async fn reload(&mut self, node: usize) {
        self.cluster.app(node).pause_building();
        self.observe().await;
        self.stop(node).await;
        self.context.sleep(RELOAD_DELAY).await;
        self.start(node, false).await;
        self.cluster.app(node).produce_continuously();
        self.observe().await;
    }

    async fn reopen_all(&mut self) {
        self.cluster.stop_producing();
        self.observe().await;
        for node in 0..NODES {
            self.stop(node).await;
        }
        self.context.sleep(RELOAD_DELAY).await;
        for node in 0..NODES {
            self.start(node, false).await;
        }
        self.cluster.produce();
        self.observe().await;
    }

    async fn apply(&mut self, byte: u8) {
        let (node, kind) = decode_action(byte);
        match kind {
            ActionKind::Reload => self.reload(node).await,
            ActionKind::InterruptRecovery => {
                self.cluster.app(node).pause_building();
                self.observe().await;
                self.stop(node).await;
                self.start(node, true).await;
                self.cluster.app(node).produce_continuously();
            }
            ActionKind::Disconnect => {
                self.set_node_network(node, NetworkState::Disconnected)
                    .await;
            }
            ActionKind::Degrade => {
                self.set_node_network(node, NetworkState::Degraded).await;
            }
            ActionKind::Heal => self.set_node_network(node, NetworkState::Healthy).await,
            ActionKind::Tick => self.context.sleep(ACTION_TICK).await,
        }
        self.observe().await;
    }

    async fn set_node_network(&mut self, node: usize, state: NetworkState) {
        self.network[node] = state;
        for peer in 0..NODES {
            if peer == node {
                continue;
            }
            self.set_link(node, peer, self.network[node].max(self.network[peer]))
                .await;
        }
    }

    async fn set_link(&self, left: usize, right: usize, state: NetworkState) {
        for (from, to) in [(left, right), (right, left)] {
            self.cluster.set_link(from, to, state.link()).await;
        }
    }

    async fn heal_all(&mut self) {
        self.network.fill(NetworkState::Healthy);
        for left in 0..NODES {
            for right in left + 1..NODES {
                self.set_link(left, right, NetworkState::Healthy).await;
            }
        }
    }

    async fn observe(&mut self) {
        let mut activities = Vec::with_capacity(NODES);
        for node in 0..NODES {
            let batch = self.reporters[node].since(self.state.nodes[node].activities);
            self.state.nodes[node].activities = self.reporters[node].len();
            activities.push(batch);
        }

        for batch in &activities {
            for activity in batch {
                let Activity::ProtocolAccepted {
                    artifact_id,
                    artifact,
                } = activity
                else {
                    continue;
                };
                self.state
                    .observe_threshold_share(artifact_id.get(), artifact);
            }
        }

        for (node, activities) in activities.into_iter().enumerate() {
            self.state
                .observe_activities(node, activities, self.resources);

            if !self.running[node] {
                continue;
            }
            let inspection = self
                .cluster
                .inspect(node)
                .await
                .unwrap_or_else(|| panic!("engine {node} stopped unexpectedly"));
            self.state
                .observe_inspection(node, &inspection, self.resources);
        }
        self.state.assert_compatible();
    }

    async fn finish(&mut self) {
        self.heal_all().await;
        self.cluster.produce();
        let baseline = self
            .state
            .nodes
            .iter()
            .map(|node| node.view)
            .collect::<Vec<_>>();
        let target_heights = (0..NODES)
            .map(|chain| {
                self.state
                    .nodes
                    .iter()
                    .map(|node| node.progress[chain].0)
                    .max()
                    .unwrap()
                    + 1
            })
            .collect::<Vec<_>>();

        for _ in 0..FINAL_TICKS {
            self.context.sleep(ACTION_TICK).await;
            self.observe().await;
            let progressed = self.state.nodes.iter().enumerate().all(|(node, state)| {
                state.view > baseline[node]
                    && state
                        .progress
                        .iter()
                        .zip(&target_heights)
                        .all(|(progress, target)| progress.0 >= *target)
            });
            if progressed {
                return;
            }
        }
        panic!("healthy suffix made no committee-wide view and finality progress");
    }

    async fn stop_all(&mut self) {
        self.observe().await;
        for node in 0..NODES {
            self.stop(node).await;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SigningSlot {
    Transaction {
        chain: u32,
        height: u64,
        signer: u32,
    },
    DaVote {
        chain: u32,
        height: u64,
        signer: u32,
    },
    Leader {
        view: u64,
        signer: u32,
    },
    Vote {
        view: u64,
        signer: u32,
    },
    NoVote {
        view: u64,
        signer: u32,
    },
    Nullify {
        view: u64,
        signer: u32,
    },
}

struct NodeState {
    activities: usize,
    signing: BTreeMap<SigningSlot, Sha256Digest>,
    stance: BTreeMap<(u64, u32), bool>,
    generation: u64,
    view: u64,
    cursor: u64,
    retired_view: u64,
    finality_floor: u64,
    progress: Vec<(u64, u64, u64)>,
    finality_by_id: BTreeMap<FinalityId<Sha256Digest>, FinalityFact<Sha256Digest>>,
    leader_by_view: BTreeMap<u64, Sha256Digest>,
    block_by_coordinate: BTreeMap<(u32, u64), BlockRef<Sha256Digest>>,
}

struct Invariants {
    epoch: Epoch,
    nodes: Vec<NodeState>,
    da_signers: BTreeMap<Sha256Digest, BTreeMap<u32, Sha256Digest>>,
    nullification_signers: BTreeMap<(u64, u64), BTreeMap<u32, Sha256Digest>>,
    view_quorum: usize,
    designation_quorum: usize,
    da_quorum: usize,
    nullification_quorum: usize,
}

impl Invariants {
    fn new(epoch: Epoch, codec: commonware_consensus::multimmit::types::CodecConfig) -> Self {
        let faults = (NODES - 1) / 5;
        let da_quorum = NODES - 2 * faults;
        let nullification_quorum = 2 * faults + 1;
        let view_quorum = NODES - faults;
        let designation_quorum = 2 * faults + 1;
        assert_eq!(codec.da_quorum(), da_quorum);
        assert_eq!(codec.nullification_quorum(), nullification_quorum);
        assert_eq!(codec.view_quorum(), view_quorum);
        assert_eq!(codec.designation_quorum(), designation_quorum);

        let nodes = (0..NODES)
            .map(|_| NodeState {
                activities: 0,
                signing: BTreeMap::new(),
                stance: BTreeMap::new(),
                generation: 0,
                view: 0,
                cursor: 0,
                retired_view: 0,
                finality_floor: 0,
                progress: vec![(0, 0, 0); NODES],
                finality_by_id: BTreeMap::new(),
                leader_by_view: BTreeMap::new(),
                block_by_coordinate: BTreeMap::new(),
            })
            .collect();
        Self {
            epoch,
            nodes,
            da_signers: BTreeMap::new(),
            nullification_signers: BTreeMap::new(),
            view_quorum,
            designation_quorum,
            da_quorum,
            nullification_quorum,
        }
    }

    fn observe_threshold_share<V: Variant>(
        &mut self,
        artifact_id: Sha256Digest,
        artifact: &Artifact<V, Sha256Digest>,
    ) {
        let (tally, signer) = match artifact {
            Artifact::DaVote(vote) => (
                self.da_signers
                    .entry(vote.header().digest::<Sha256>())
                    .or_default(),
                vote.signer().get(),
            ),
            Artifact::Nullify(vote) => (
                self.nullification_signers
                    .entry((vote.round().epoch().get(), vote.round().view().get()))
                    .or_default(),
                vote.signer().get(),
            ),
            _ => return,
        };
        assert!(
            (signer as usize) < NODES,
            "threshold signer is in the committee"
        );
        if let Some(previous) = tally.insert(signer, artifact_id) {
            assert_eq!(
                previous, artifact_id,
                "threshold signer produced conflicting shares for one subject"
            );
        }
    }

    fn observe_activities<V: Variant>(
        &mut self,
        node: usize,
        activities: Vec<Activity<V, Sha256Digest>>,
        resources: ResourceLimits,
    ) {
        for activity in activities {
            let Activity::ProtocolAccepted {
                artifact_id,
                artifact,
            } = activity
            else {
                continue;
            };
            assert_eq!(artifact_id, artifact.id::<Sha256>());
            assert!(artifact.encoded_len() <= resources.max_artifact_bytes());
            self.observe_thresholds(&artifact);
            self.observe_signing(node, artifact_id.get(), &artifact);
        }
    }

    fn observe_thresholds<V: Variant>(&self, artifact: &Artifact<V, Sha256Digest>) {
        match artifact {
            Artifact::Vqc(certificate) => {
                let designated = certificate.tally().signers().count();
                let accounted = designated
                    + certificate.novoters().count()
                    + certificate.conflicting_votes().len();
                assert!(designated >= self.designation_quorum);
                assert!((self.view_quorum..=NODES).contains(&accounted));
            }
            Artifact::Lqc(certificate) => {
                assert_eq!(certificate.tally().signers().count(), self.view_quorum);
            }
            Artifact::DaCertificate(certificate) => {
                let subject = certificate.header().digest::<Sha256>();
                let tally = self
                    .da_signers
                    .get(&subject)
                    .expect("accepted DA certificate has observed shares");
                assert!(signer_tally_is_valid(
                    tally.keys().copied(),
                    NODES,
                    self.da_quorum
                ));
            }
            Artifact::Nullification(certificate) => {
                let round = certificate.round();
                let subject = (round.epoch().get(), round.view().get());
                let tally = self
                    .nullification_signers
                    .get(&subject)
                    .expect("accepted nullification has observed shares");
                assert!(signer_tally_is_valid(
                    tally.keys().copied(),
                    NODES,
                    self.nullification_quorum
                ));
            }
            _ => {}
        }
    }

    fn observe_signing<V: Variant>(
        &mut self,
        node: usize,
        artifact_id: Sha256Digest,
        artifact: &Artifact<V, Sha256Digest>,
    ) {
        let Some(signer) = artifact.signer() else {
            return;
        };
        if signer.get() as usize != node {
            return;
        }
        let signer = signer.get();
        let slot = match artifact {
            Artifact::TransactionBlock(block) => SigningSlot::Transaction {
                chain: block.header().chain().get(),
                height: block.height().get(),
                signer,
            },
            Artifact::DaVote(vote) => SigningSlot::DaVote {
                chain: vote.header().chain().get(),
                height: vote.height().get(),
                signer,
            },
            Artifact::LeaderBlock(block) => SigningSlot::Leader {
                view: block.block().round().view().get(),
                signer,
            },
            Artifact::Vote(vote) => {
                let view = vote.body().round().view().get();
                assert_ne!(
                    self.nodes[node].stance.insert((view, signer), true),
                    Some(false)
                );
                SigningSlot::Vote { view, signer }
            }
            Artifact::NoVote(vote) => {
                let view = vote.round().view().get();
                assert_ne!(
                    self.nodes[node].stance.insert((view, signer), false),
                    Some(true)
                );
                SigningSlot::NoVote { view, signer }
            }
            Artifact::Nullify(vote) => SigningSlot::Nullify {
                view: vote.round().view().get(),
                signer,
            },
            Artifact::DaCertificate(_)
            | Artifact::Nullification(_)
            | Artifact::Vqc(_)
            | Artifact::Lqc(_) => return,
        };
        if let Some(previous) = self.nodes[node].signing.insert(slot, artifact_id) {
            assert_eq!(
                previous, artifact_id,
                "local signing subject changed after reopen"
            );
        }
    }

    fn observe_inspection(
        &mut self,
        node: usize,
        inspection: &Inspection<Sha256Digest>,
        resources: ResourceLimits,
    ) {
        assert_eq!(inspection.epoch(), self.epoch);
        assert!(inspection.is_live());
        assert!(!inspection.is_recovering());
        assert!(inspection.retired_view() < inspection.view());
        assert!(inspection.nullification_suffix() <= inspection.view().get());
        assert!(inspection.cached_artifacts() <= resources.max_cached_artifacts());
        assert!(inspection.retained_artifact_references() <= resources.max_cached_artifacts());
        assert!(inspection.verification_jobs_len() <= resources.max_inflight_verifications());
        assert!(inspection.future_artifacts() <= resources.max_future_artifacts());
        assert!(inspection.resolution_jobs() <= resources.max_dependency_waiters());
        assert!(inspection.outbox_len() <= resources.max_outbox_effects());
        assert_eq!(
            inspection.pending_artifacts()
                + inspection.waiting_artifacts()
                + inspection.ready_artifacts().len()
                + inspection.dropped_artifacts(),
            inspection.cached_artifacts()
        );
        assert!(inspection.future_artifacts() <= inspection.cached_artifacts());

        let state = &mut self.nodes[node];
        assert!(inspection_generation(inspection) >= state.generation);
        assert!(inspection.view().get() >= state.view);
        assert!(inspection_cursor(inspection) >= state.cursor);
        assert!(inspection.retired_view().get() >= state.retired_view);
        assert!(inspection.finality_floor().get() >= state.finality_floor);
        state.generation = inspection_generation(inspection);
        state.view = inspection.view().get();
        state.cursor = inspection_cursor(inspection);
        state.retired_view = inspection.retired_view().get();
        state.finality_floor = inspection.finality_floor().get();

        assert_eq!(inspection.chain_progress().len(), NODES);
        for (chain, progress) in inspection.chain_progress().iter().copied().enumerate() {
            assert_eq!(progress.chain(), ChainId::new(chain as u32));
            assert!(progress.finalized() <= progress.known());
            assert!(progress.certified() <= progress.known());
            state.progress[chain] = (
                progress.finalized().get(),
                progress.certified().get(),
                progress.known().get(),
            );
        }
        for pool in inspection.pools() {
            assert_eq!(pool.round().epoch(), self.epoch);
            assert!(pool.votes() <= NODES);
            assert_eq!(pool.finalized(), pool.votes() >= self.view_quorum);
            assert!(!pool.lqc_pending() || pool.finalized());
        }
        for fact in inspection.finality() {
            assert_eq!(fact.round().epoch(), self.epoch);
            assert!((self.view_quorum..=NODES).contains(&fact.votes()));
            assert_eq!(fact.blocks().len(), NODES);
            assert_eq!(fact.positions().len(), NODES);
            assert_eq!(fact.settled().len(), NODES);

            if let Some(previous) = state.finality_by_id.insert(fact.id(), fact.clone()) {
                assert_eq!(previous, *fact, "identical finality evidence changed");
            }
            let view = fact.round().view().get();
            if let Some(previous) = state.leader_by_view.insert(view, fact.leader()) {
                assert_eq!(previous, fact.leader(), "one view finalized two leaders");
            }
            for (chain, block) in fact.blocks().iter().copied().enumerate() {
                assert_eq!(block.chain(), ChainId::new(chain as u32));
                let coordinate = (block.chain().get(), block.height().get());
                if let Some(previous) = state.block_by_coordinate.insert(coordinate, block) {
                    assert_eq!(previous, block, "one chain coordinate finalized two blocks");
                }
            }
        }
        if let Some(producer) = inspection.producer() {
            assert_eq!(producer.chain(), ChainId::new(node as u32));
            assert_eq!(producer.da_quorum(), self.da_quorum);
            assert!(producer.certified() <= producer.produced());
            assert!(
                producer
                    .produced()
                    .get()
                    .saturating_sub(producer.certified().get())
                    <= producer.pipeline_depth()
            );
        }
    }

    fn assert_compatible(&self) {
        for left in 0..NODES {
            for right in left + 1..NODES {
                let left = &self.nodes[left];
                let right = &self.nodes[right];
                for (id, fact) in &left.finality_by_id {
                    if let Some(other) = right.finality_by_id.get(id) {
                        assert_eq!(fact, other, "nodes disagree on exact finality evidence");
                    }
                }
                for (view, leader) in &left.leader_by_view {
                    if let Some(other) = right.leader_by_view.get(view) {
                        assert_eq!(
                            leader, other,
                            "nodes finalized different leaders in one view"
                        );
                    }
                }
                for (coordinate, block) in &left.block_by_coordinate {
                    if let Some(other) = right.block_by_coordinate.get(coordinate) {
                        assert_eq!(block, other, "nodes finalized different chain blocks");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::primitives::variant::MinPk;

    #[test]
    fn seeded_repeated_custody_recovery() {
        const SEED: u64 = 0xC0570D;
        deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(SEED)
                .with_timeout(Some(RUNNER_TIMEOUT)),
        )
        .start(|context| async move {
            let mut harness = Harness::<MinPk>::new(context, SEED).await;
            harness.cluster.app(0).pause_building();
            harness.start(0, false).await;
            for _ in 0..2 {
                harness.stop(0).await;
                assert!(
                    !harness.start(0, true).await,
                    "a fresh store has no recovery custody to interrupt"
                );
            }
            for node in 1..NODES {
                harness.start(node, false).await;
            }
            harness.observe().await;
            harness.cluster.app(0).produce_continuously();
            harness.finish().await;
            for _ in 0..2 {
                harness.cluster.app(0).pause_building();
                harness.observe().await;
                harness.stop(0).await;
                assert!(
                    harness.start(0, true).await,
                    "durable payloads must reach the interrupted recovery custody fence"
                );
                harness.cluster.app(0).produce_continuously();
                harness.finish().await;
            }
            harness.stop_all().await;
        });
    }

    #[test]
    fn partitioned_quiet_node_stops() {
        // Node one is cut off after voting in view one, leaving a reconstructible barrier that no
        // later input demands durability for when the checkpoint reopens every node.
        fuzz::<MinPk>(&[7]);
    }

    #[test]
    fn every_action_kind_campaign_stops() {
        // Every action kind on distinct nodes on both sides of the reopen checkpoint; this
        // campaign hung in stop before the harness demanded durability.
        fuzz::<MinPk>(&[0, 7, 14, 21, 28, 35, 2, 9, 16, 23, 30, 5]);
    }

    #[test]
    fn input_is_bounded_before_use() {
        let input = (0..=u8::MAX).collect::<Vec<_>>();
        let bounded = bounded_input(&input);

        assert_eq!(bounded, &input[..MAX_INPUT_BYTES]);
        assert_eq!(bounded.as_ptr(), input.as_ptr());
    }

    #[test]
    fn every_node_action_pair_is_reachable() {
        let decoded = (0..NODES * ACTION_KINDS)
            .map(|byte| decode_action(byte as u8))
            .collect::<BTreeSet<_>>();

        assert_eq!(decoded.len(), NODES * ACTION_KINDS);
        for node in 0..NODES {
            for kind in [
                ActionKind::Reload,
                ActionKind::InterruptRecovery,
                ActionKind::Disconnect,
                ActionKind::Degrade,
                ActionKind::Heal,
                ActionKind::Tick,
            ] {
                assert!(decoded.contains(&(node, kind)));
            }
        }
    }

    #[test]
    fn network_faults_compose_by_strongest_endpoint() {
        assert_eq!(
            NetworkState::Disconnected.max(NetworkState::Degraded),
            NetworkState::Disconnected
        );
        assert_eq!(
            NetworkState::Healthy.max(NetworkState::Degraded),
            NetworkState::Degraded
        );
    }

    #[test]
    fn signer_tally_requires_unique_in_range_quorum() {
        assert!(signer_tally_is_valid([0, 1, 2, 3], NODES, 4));
        assert!(!signer_tally_is_valid([0, 1, 1, 2], NODES, 4));
        assert!(!signer_tally_is_valid([0, 1, 2], NODES, 4));
        assert!(!signer_tally_is_valid([0, 1, 2, NODES as u32], NODES, 4));
    }
}

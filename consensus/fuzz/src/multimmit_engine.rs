//! Byte-driven crash, recovery, and network scheduling for production Multimmit engines.
//!
//! A six-node cluster of complete engines runs under a schedule of reloads, interrupted opens,
//! and per-node link faults, with every node restarted at the schedule's midpoint, then heals and
//! must make progress. Throughout, the harness checks the agreement facts every node reports
//! against each other and against their own commitments, and every node's inspection against its
//! resource limits and its previous inspections.

use commonware_consensus::{
    Epochable as _, Viewable as _,
    multimmit::{
        Inspection,
        mocks::{
            RecordingReporter,
            cluster::{Cluster, ClusterOptions, Launch, LaunchSpec},
        },
        test_utils::{ResourceLimits, inspection_cursor, inspection_generation, resource_limits},
        types::{Activity, BlockRef, ChainId, ChainSet, EpochGenesis, HistoryRecord},
    },
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::Variant, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Link;
use commonware_runtime::{Clock as _, Runner as _, deterministic};
use commonware_utils::{FuzzRng, probability};
use std::{collections::BTreeMap, time::Duration};

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
    InterruptOpen,
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
        5 => ActionKind::InterruptOpen,
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
        let state = Invariants::new(committee.config.epoch(), committee.genesis());

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
            self.start(node).await;
        }
        self.observe().await;
    }

    async fn start(&mut self, node: usize) {
        assert!(!self.running[node], "start requires a stopped engine");
        // The previous process's reports belong to the checks it was subject to.
        self.drain(node);
        self.state.nodes[node].restarted();
        let spec = LaunchSpec::new(node).reporter(self.reporters[node].clone());
        self.cluster.launch(spec).await;
        self.cluster.await_ready(&[node]).await;
        self.running[node] = true;
    }

    /// Opens `node` but abandons the open after a delay if it has not started by then, then
    /// starts it.
    ///
    /// An abandoned open must leave no trace: nothing reported and nothing proposed.
    async fn interrupt_open(&mut self, node: usize) {
        assert!(!self.running[node], "open requires a stopped engine");
        let reports = self.reporters[node].len();
        let proposed = self.cluster.app(node).log().lock().proposed;
        let spec = LaunchSpec::new(node).reporter(self.reporters[node].clone());
        let interrupt = self.context.sleep(RELOAD_DELAY);
        match self.cluster.launch_racing(spec, interrupt).await {
            Launch::Started => {
                self.drain(node);
                self.state.nodes[node].restarted();
                self.cluster.await_ready(&[node]).await;
                self.running[node] = true;
            }
            Launch::Interrupted(()) => {
                assert_eq!(self.reporters[node].len(), reports);
                assert_eq!(self.cluster.app(node).log().lock().proposed, proposed);
                self.start(node).await;
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

    async fn reopen_all(&mut self) {
        self.cluster.stop_producing();
        self.observe().await;
        for node in 0..NODES {
            self.stop(node).await;
        }
        self.context.sleep(RELOAD_DELAY).await;
        for node in 0..NODES {
            self.start(node).await;
        }
        self.cluster.produce();
        self.observe().await;
    }

    async fn apply(&mut self, byte: u8) {
        let (node, kind) = decode_action(byte);
        match kind {
            ActionKind::Reload => {
                self.cluster.app(node).pause_building();
                self.observe().await;
                self.stop(node).await;
                self.context.sleep(RELOAD_DELAY).await;
                self.start(node).await;
                self.cluster.app(node).produce_continuously();
            }
            ActionKind::InterruptOpen => {
                self.cluster.app(node).pause_building();
                self.observe().await;
                self.stop(node).await;
                self.interrupt_open(node).await;
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
        for node in 0..NODES {
            self.drain(node);
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
    }

    /// Checks every activity `node` reported since the last drain.
    fn drain(&mut self, node: usize) {
        let activities = self.reporters[node].since(self.state.nodes[node].activities);
        self.state.nodes[node].activities = self.reporters[node].len();
        for activity in activities {
            self.state.observe_activity(node, activity);
        }
    }

    /// Heals every link and waits until every node resolves a newer view whose tips advance
    /// every chain past the highest tip any node had resolved.
    async fn finish(&mut self) {
        self.heal_all().await;
        self.cluster.produce();
        let baseline = self
            .state
            .nodes
            .iter()
            .map(|node| node.resolved)
            .collect::<Vec<_>>();
        let targets = (0..NODES)
            .map(|chain| self.state.resolved_height(chain) + 1)
            .collect::<Vec<_>>();

        for _ in 0..FINAL_TICKS {
            self.context.sleep(ACTION_TICK).await;
            self.observe().await;
            let progressed = self
                .state
                .nodes
                .iter()
                .zip(&baseline)
                .all(|(node, baseline)| {
                    node.resolved > *baseline
                        && self
                            .state
                            .views
                            .get(&node.resolved)
                            .is_some_and(|resolved| {
                                resolved
                                    .tips
                                    .iter()
                                    .zip(&targets)
                                    .all(|(tip, target)| tip.height().get() >= *target)
                            })
                });
            if progressed {
                return;
            }
        }
        let resolved = self
            .state
            .nodes
            .iter()
            .map(|node| node.resolved)
            .collect::<Vec<_>>();
        let views = self
            .state
            .nodes
            .iter()
            .map(|node| node.view)
            .collect::<Vec<_>>();
        panic!(
            "healed cluster made no committee-wide resolution progress on every chain: \
             resolved {resolved:?} from {baseline:?} in views {views:?}, target heights \
             {targets:?}"
        );
    }

    async fn stop_all(&mut self) {
        self.observe().await;
        for node in 0..NODES {
            self.stop(node).await;
        }
    }
}

/// A resolved view as every node must report it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Resolved {
    tips: Vec<BlockRef<Sha256Digest>>,
    commitment: Sha256Digest,
    parent_commitment: Sha256Digest,
}

#[derive(Default)]
struct NodeState {
    /// Reporter activities already observed.
    activities: usize,
    /// Newest view this node reported resolved.
    resolved: u64,
    /// Newest sweep this process reported: its view, final tip heights, and settled set.
    sweep: Option<(u64, Vec<u64>, ChainSet)>,
    generation: u64,
    cursor: u64,
    view: u64,
    retired_view: u64,
    last_resolved: u64,
}

impl NodeState {
    /// Forgets what a restart may legitimately re-report from an earlier point.
    fn restarted(&mut self) {
        self.sweep = None;
    }
}

/// Facts every node must agree on, accumulated from all reports.
struct Invariants {
    epoch: Epoch,
    nodes: Vec<NodeState>,
    /// Resolved views, starting with the genesis tips and history at view zero.
    views: BTreeMap<u64, Resolved>,
    /// Finalized leader block per view.
    leaders: BTreeMap<u64, Sha256Digest>,
    /// The one header accepted or proposed per chain coordinate.
    headers: BTreeMap<(ChainId, u64), Sha256Digest>,
}

impl Invariants {
    fn new(epoch: Epoch, genesis: &EpochGenesis<Sha256Digest>) -> Self {
        let genesis = Resolved {
            tips: genesis.tips().to_vec(),
            commitment: genesis.history(),
            parent_commitment: genesis.history(),
        };
        Self {
            epoch,
            nodes: (0..NODES).map(|_| NodeState::default()).collect(),
            views: BTreeMap::from([(0, genesis)]),
            leaders: BTreeMap::new(),
            headers: BTreeMap::new(),
        }
    }

    /// Returns the height of `chain`'s tip in the newest resolved view any node reported.
    fn resolved_height(&self, chain: usize) -> u64 {
        self.views
            .values()
            .next_back()
            .and_then(|resolved| resolved.tips.get(chain))
            .map_or(0, |tip| tip.height().get())
    }

    /// Records the header at `block`'s coordinate; correct producers sign one per height.
    fn observe_header(&mut self, block: BlockRef<Sha256Digest>) {
        let coordinate = (block.chain(), block.height().get());
        if let Some(previous) = self.headers.insert(coordinate, block.digest()) {
            assert_eq!(
                previous,
                block.digest(),
                "two headers at one chain coordinate"
            );
        }
    }

    fn observe_activity<V: Variant>(&mut self, node: usize, activity: Activity<V, Sha256Digest>) {
        match activity {
            Activity::TransactionProposed { block, .. } => {
                assert_eq!(block.chain(), ChainId::new(node as u32));
                self.observe_header(block);
            }
            Activity::HeaderAccepted { header, .. } => {
                assert_eq!(header.epoch(), self.epoch);
                self.observe_header(header.block_ref::<Sha256>());
            }
            Activity::ViewResolved {
                view,
                base,
                tips,
                commitment,
                parent_commitment,
                ..
            } => {
                let view = view.get();
                assert!(view > 0, "genesis is never resolved");
                let record = HistoryRecord::new(parent_commitment, tips.to_vec())
                    .expect("resolved tips are one per chain");
                assert_eq!(record.commitment::<Sha256>(), commitment);
                assert_eq!(tips.len(), NODES);
                for (tip, base) in tips.iter().zip(base.iter()) {
                    assert!(tip.height() >= base.height(), "a resolved tip regresses");
                }
                let state = &mut self.nodes[node];
                assert!(
                    view <= state.resolved + 1,
                    "node {node} skipped from view {} to {view}",
                    state.resolved
                );
                state.resolved = state.resolved.max(view);
                if let Some(previous) = self.views.get(&(view - 1)) {
                    assert_eq!(previous.commitment, parent_commitment);
                    assert_eq!(previous.tips.as_slice(), base.as_ref());
                }
                let resolved = Resolved {
                    tips: tips.to_vec(),
                    commitment,
                    parent_commitment,
                };
                if let Some(previous) = self.views.insert(view, resolved.clone()) {
                    assert_eq!(previous, resolved, "nodes resolved view {view} differently");
                }
            }
            Activity::ViewSweep {
                view,
                finals,
                settled,
            } => {
                let view = view.get();
                assert_eq!(finals.len(), NODES);
                assert_eq!(settled.chains(), NODES);
                let heights = finals
                    .iter()
                    .map(|tip| tip.height().get())
                    .collect::<Vec<_>>();
                // A sweep's blocks are in every correct log: at or below the view's tips, and a
                // settled chain gains nothing past its final tip.
                if let Some(resolved) = self.views.get(&view) {
                    for (chain, (last, tip)) in finals.iter().zip(&resolved.tips).enumerate() {
                        assert!(last.height() <= tip.height(), "sweep passes the view's tip");
                        if last.height() == tip.height()
                            || settled.contains(ChainId::new(chain as u32))
                        {
                            assert_eq!(last, tip, "sweep conflicts with the view's tip");
                        }
                    }
                }
                let state = &mut self.nodes[node];
                if let Some((previous, last, members)) = &state.sweep
                    && *previous == view
                {
                    assert!(
                        last.iter().zip(&heights).all(|(last, next)| last <= next),
                        "sweep retreats within a view"
                    );
                    assert!(
                        (0..NODES)
                            .map(|chain| ChainId::new(chain as u32))
                            .all(|chain| !members.contains(chain) || settled.contains(chain)),
                        "settled chain unsettles within a view"
                    );
                }
                state.sweep = Some((view, heights, settled));
            }
            Activity::LeaderFinalized { lqc, opening } => {
                let leader = lqc.leader();
                assert_eq!(lqc.epoch(), self.epoch);
                assert_eq!(opening.commitment::<Sha256>(), leader.history());
                let view = lqc.view().get();
                let digest = leader.digest::<Sha256>();
                if let Some(previous) = self.leaders.insert(view, digest) {
                    assert_eq!(
                        previous, digest,
                        "two leader blocks finalized in view {view}"
                    );
                }
                if let Some(resolved) = self.views.get(&(view - 1)) {
                    assert_eq!(resolved.commitment, leader.history());
                    assert_eq!(resolved.tips.as_slice(), opening.tips());
                }
            }
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
        // The current view's own final votes can fix the next view's base before its V-QC forms.
        assert!(inspection.last_resolved() <= inspection.view().next());
        assert!(inspection.cached_artifacts() <= resources.max_cached_artifacts());
        assert!(inspection.verification_jobs_len() <= resources.max_inflight_verifications());
        assert!(inspection.resolution_jobs() <= resources.max_dependency_waiters());
        assert!(inspection.outbox_len() <= resources.max_outbox_effects());
        assert!(
            inspection.pending_artifacts()
                + inspection.waiting_artifacts()
                + inspection.ready_artifacts().len()
                <= inspection.cached_artifacts()
        );

        // Every barrier is durable before a crash, so progress never regresses across restarts.
        let state = &mut self.nodes[node];
        assert!(inspection_generation(inspection) >= state.generation);
        assert!(inspection_cursor(inspection) >= state.cursor);
        assert!(inspection.view().get() >= state.view);
        assert!(inspection.retired_view().get() >= state.retired_view);
        assert!(inspection.last_resolved().get() >= state.last_resolved);
        state.generation = inspection_generation(inspection);
        state.cursor = inspection_cursor(inspection);
        state.view = inspection.view().get();
        state.retired_view = inspection.retired_view().get();
        state.last_resolved = inspection.last_resolved().get();

        assert_eq!(inspection.chain_progress().len(), NODES);
        for (chain, progress) in inspection.chain_progress().iter().enumerate() {
            assert_eq!(progress.chain(), ChainId::new(chain as u32));
        }
        if let Some(producer) = inspection.producer() {
            assert_eq!(producer.chain(), ChainId::new(node as u32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use std::collections::BTreeSet;

    #[test]
    fn partitioned_quiet_node_stops() {
        // Node one is cut off early, leaving a reconstructible barrier that no later input
        // demands durability for when the checkpoint reopens every node.
        fuzz::<MinPk>(&[7]);
    }

    #[test]
    fn every_action_kind_campaign_stops() {
        // Every action kind on distinct nodes on both sides of the reopen checkpoint.
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
                ActionKind::InterruptOpen,
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
}

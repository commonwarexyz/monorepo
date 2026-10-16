//! A world of real machines joined by a scheduled network, checked by [`Oracle`].
//!
//! Each node runs the production machine through a [`Driver`]: a symbolic journal it appends to and
//! acknowledges one barrier at a time, real signatures from its participant's keys, real batch
//! verification, symbolic block building and certificate aggregation, and a resolver serving
//! what peers published or retained. A [`Schedule`] picks every step while it lasts: which node
//! acts, which queued message it receives (reordered, duplicated, or dropped), which issued
//! capability completes next, when barriers are appended and acknowledged, when time passes, and
//! when a node crashes before or after appending a barrier. A world then runs a fair suffix:
//! every node drains its work in order, and time jumps to the earliest armed deadline, or by one
//! millisecond while a retrieval can be answered: a retrieval takes network time, so a key the
//! machine fetches again after refusing the answer costs one round trip per attempt.
//!
//! Twin halves are two nodes acting for one participant, with its keys; a [`Router`] decides
//! which nodes receive each published message and whose retained artifacts a node may fetch.

mod oracle;
#[cfg(test)]
mod tests;

use super::{
    Drive as _, Driver,
    fixtures::{TestDriver, tuned},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::verifier::verify,
        config::{Role, Tuning},
        machine::{
            capability::{AppJob, Capability, ChainCommand, CryptoJob, ResolverCommand},
            durability::{DurableEffect, DurableJob, EffectCompletion, PersistJob, Publication},
            input::{
                Aggregated, BlockValidity, BuildCompletion, CryptoCompletion, CustodyCompletion,
                Input, Step, TimerFamily, ValidationCompletion,
            },
            reducer::machine::Machine,
            resolution::{ResolutionCompletion, ResolutionJob, RetrievalKey},
        },
        mocks::Committee,
        scheme::bls12381::SignatureVerification,
        types::{Activity, Artifact, CertificateId, ChainId},
    },
    types::{Attributable as _, Participant, View},
};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
pub(crate) use oracle::Oracle;
use rand::RngExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};

/// An artifact as the world carries it.
pub(crate) type WorldArtifact = Artifact<MinPk, Digest>;

/// One network message: the artifacts one frame carries, observed together.
pub(crate) type Message = Vec<Arc<WorldArtifact>>;

/// The most units of work the world runs without time passing before it reports a livelock.
const MAX_SETTLE_UNITS: usize = 1_000_000;

/// The most steps a fair suffix runs before it reports that the world stopped making progress.
const MAX_FAIR_STEPS: usize = 200_000;

/// The source of every adversarial choice a world makes.
pub(crate) trait Schedule {
    /// Returns a choice in `0..bound` (`bound > 0`), or `None` once the schedule is exhausted.
    fn choose(&mut self, bound: usize) -> Option<usize>;
}

/// A schedule of `choices` choices drawn from a seeded generator.
pub(crate) struct Seeded {
    rng: TestRng,
    choices: usize,
}

impl Seeded {
    /// Creates a schedule of `choices` choices drawn from `seed`.
    pub(crate) fn new(seed: u64, choices: usize) -> Self {
        Self {
            rng: TestRng::new(seed),
            choices,
        }
    }
}

impl Schedule for Seeded {
    fn choose(&mut self, bound: usize) -> Option<usize> {
        self.choices = self.choices.checked_sub(1)?;
        Some(self.rng.random_range(0..bound))
    }
}

/// A schedule reading one choice per byte.
pub(crate) struct Bytes<'a> {
    data: &'a [u8],
}

impl<'a> Bytes<'a> {
    /// Creates a schedule over `data`.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl Schedule for Bytes<'_> {
    fn choose(&mut self, bound: usize) -> Option<usize> {
        let (first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(usize::from(*first) % bound)
    }
}

/// Decides where messages go and who serves retrievals.
pub(crate) trait Router {
    /// Returns the nodes, among `nodes` and other than `from`, that receive `message` published
    /// by node `from`.
    fn recipients(
        &mut self,
        nodes: usize,
        from: usize,
        message: &[Arc<WorldArtifact>],
    ) -> Vec<usize>;

    /// Returns whether node `server` answers node `client`'s retrievals.
    fn serves(&self, server: usize, client: usize) -> bool;
}

/// Delivers every message to every other node and lets every node serve every other.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Broadcast;

impl Router for Broadcast {
    fn recipients(&mut self, nodes: usize, from: usize, _: &[Arc<WorldArtifact>]) -> Vec<usize> {
        (0..nodes).filter(|node| *node != from).collect()
    }

    fn serves(&self, _: usize, _: usize) -> bool {
        true
    }
}

/// How a node verifies signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verification {
    /// Batch-verify every item with the production verifier.
    Real,
    /// Accept every item; every artifact in such a world is honestly signed.
    Symbolic,
}

/// When a crash interrupts a node's journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cut {
    /// Before the next barrier is appended: the barrier is lost.
    BeforeAppend,
    /// After the next barrier is appended and before it is acknowledged.
    BeforeAcknowledge,
}

/// One node: a machine acting for one participant and what it has not processed yet.
pub(crate) struct Node {
    participant: Participant,
    /// Distinguishes the bodies twin halves build on one parent.
    salt: u8,
    driver: TestDriver,
    /// Issued capabilities not executed yet, in issuance order.
    pending: VecDeque<Capability<MinPk, Digest>>,
    /// Barriers the journal accepted and has not appended, in cursor order.
    journal: VecDeque<PersistJob<MinPk, Digest>>,
    /// Appended barriers not acknowledged yet, in cursor order.
    appended: VecDeque<PersistJob<MinPk, Digest>>,
    /// Received messages not observed yet.
    inbox: VecDeque<Message>,
    /// Inputs held while the machine has no persistence capacity: the voter then takes only
    /// barrier acknowledgements.
    deferred: VecDeque<Input<MinPk, Digest>>,
    /// Outstanding retrievals.
    retrievals: Vec<ResolutionJob<Digest>>,
    /// The time of the node's latest completed build.
    last_built: Option<u64>,
    /// A build requested in the millisecond of the previous one, held until the clock advances:
    /// each node builds at most one block per millisecond, so production cannot fill windows in a
    /// world where no time passes, while a producer that was idle builds at once.
    built: Option<Input<MinPk, Digest>>,
    /// What this node publishes or retains, by the key a peer retrieves it with.
    served: BTreeMap<RetrievalKey<Digest>, Arc<WorldArtifact>>,
    /// Barriers appended since the start.
    barriers: usize,
    /// The epoch's producer chains.
    chains: usize,
}

impl Node {
    /// Returns the node's machine.
    pub(crate) const fn machine(&self) -> &Machine<Sha256, MinPk> {
        self.driver.machine()
    }

    /// Serves `artifact` under every key it answers. A sender's vote of a tag is served as its
    /// latest update naming every chain, as the resolver serves it; other updates are not served.
    /// The newest floor replaces older ones.
    fn serve(&mut self, artifact: &Arc<WorldArtifact>) {
        if let Artifact::Floor(floor) = artifact.as_ref() {
            let newer = self
                .served
                .get(&RetrievalKey::LatestFloor)
                .is_none_or(|served| served.view() < Some(floor.lqc().view()));
            if newer {
                self.served
                    .insert(RetrievalKey::LatestFloor, Arc::clone(artifact));
            }
            return;
        }
        if let Artifact::Update(update) = artifact.as_ref() {
            if update.changes().len() != self.chains {
                return;
            }
            let key = RetrievalKey::Update {
                signer: update.signer(),
                view: update.view(),
            };
            let newer = self.served.get(&key).is_none_or(|served| {
                matches!(served.as_ref(), Artifact::Update(served) if served.seq() < update.seq())
            });
            if newer {
                self.served.insert(key, Arc::clone(artifact));
            }
            return;
        }
        for key in keys(artifact) {
            self.served
                .entry(key)
                .or_insert_with(|| Arc::clone(artifact));
        }
    }
}

/// Builds a [`World`].
pub(crate) struct Config {
    /// The epoch committee.
    pub(crate) committee: Committee<MinPk>,
    /// The participant each node acts for, in node order; a participant listed twice runs as
    /// twin halves.
    pub(crate) nodes: Vec<Participant>,
    /// Participants that may equivocate.
    pub(crate) byzantine: BTreeSet<Participant>,
    /// Every node's tuning.
    pub(crate) tuning: Tuning,
    /// How nodes verify signatures.
    pub(crate) verification: Verification,
}

impl Config {
    /// Returns a world of one correct node per participant of `committee`.
    pub(crate) fn correct(committee: Committee<MinPk>) -> Self {
        let participants = committee.codec().participants();
        Self {
            committee,
            nodes: (0..participants).map(Participant::from_usize).collect(),
            byzantine: BTreeSet::new(),
            tuning: Tuning::default(),
            verification: Verification::Real,
        }
    }
}

/// A world of machines, a router, and the oracle checking them.
pub(crate) struct World<R: Router = Broadcast> {
    committee: Committee<MinPk>,
    verification: Verification,
    nodes: Vec<Node>,
    router: R,
    oracle: Oracle,
    now: u64,
    rng: TestRng,
    /// A crash scheduled at a node's n-th appended barrier.
    crash_at: Option<(usize, usize, Cut)>,
}

impl<R: Router> World<R> {
    /// Starts every node of `config` under `router`.
    pub(crate) fn new(config: Config, router: R) -> Self {
        let Config {
            committee,
            nodes,
            byzantine,
            tuning,
            verification,
        } = config;
        let oracle = Oracle::new(
            committee.genesis().epoch(),
            committee.codec(),
            committee.verifier.clone(),
            committee.genesis().tips().to_vec(),
            byzantine,
            nodes.iter().copied(),
        );
        let mut counts = BTreeMap::<Participant, u8>::new();
        let nodes = nodes
            .into_iter()
            .map(|participant| {
                let salt = counts.entry(participant).or_default();
                *salt += 1;
                Node {
                    participant,
                    salt: *salt,
                    driver: Driver::new(tuned(&committee, Role::Validator(participant), tuning)),
                    pending: VecDeque::new(),
                    journal: VecDeque::new(),
                    appended: VecDeque::new(),
                    inbox: VecDeque::new(),
                    deferred: VecDeque::new(),
                    retrievals: Vec::new(),
                    last_built: None,
                    built: None,
                    served: BTreeMap::new(),
                    barriers: 0,
                    chains: committee.codec().chains(),
                }
            })
            .collect();
        let mut world = Self {
            committee,
            verification,
            nodes,
            router,
            oracle,
            now: 0,
            rng: TestRng::new(0),
            crash_at: None,
        };
        for node in 0..world.nodes.len() {
            world.submit(node, Input::Start);
        }
        world
    }

    /// Returns the nodes.
    pub(crate) fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Returns the oracle.
    pub(crate) const fn oracle(&self) -> &Oracle {
        &self.oracle
    }

    /// Returns the router.
    pub(crate) const fn router_mut(&mut self) -> &mut R {
        &mut self.router
    }

    /// Returns the committee.
    pub(crate) const fn committee(&self) -> &Committee<MinPk> {
        &self.committee
    }

    /// Returns the identifier and history commitment of the V-QC of the view before `view` that
    /// `node` holds first.
    ///
    /// # Panics
    ///
    /// Panics unless `node` holds one.
    pub(crate) fn entry(&self, node: usize, view: View) -> (CertificateId<Digest>, Digest) {
        let previous = view.previous().expect("views above genesis follow one");
        let held = self.nodes[node]
            .machine()
            .components
            .vqcs
            .first(previous)
            .expect("the node holds a V-QC of the previous view");
        (held.held.id, held.held.history)
    }

    /// Crashes `node` at its `barrier`-th appended barrier during later steps.
    pub(crate) const fn crash_at(&mut self, node: usize, barrier: usize, cut: Cut) {
        self.crash_at = Some((node, barrier, cut));
    }

    /// Returns the crash scheduled by [`Self::crash_at`] that has not happened yet.
    pub(crate) const fn crash_pending(&self) -> Option<(usize, usize, Cut)> {
        self.crash_at
    }

    /// Queues `message` for `node` as if a peer sent it.
    pub(crate) fn inject(&mut self, node: usize, message: Message) {
        for artifact in &message {
            self.oracle.published(artifact);
        }
        self.nodes[node].inbox.push_back(message);
    }

    /// Runs adversarial steps until `schedule` is exhausted.
    pub(crate) fn adversarial(&mut self, schedule: &mut impl Schedule) {
        while self.step(schedule).is_some() {}
    }

    /// Runs the fair suffix until `done` holds, jumping time to the earliest armed deadline
    /// whenever every node is idle.
    ///
    /// # Panics
    ///
    /// Panics if `done` does not hold within `millis` of simulated time.
    pub(crate) fn run_until(&mut self, millis: u64, mut done: impl FnMut(&Self) -> bool) {
        let deadline = self.now + millis;
        for _ in 0..MAX_FAIR_STEPS {
            self.settle();
            if done(self) {
                return;
            }
            let retrieving = (0..self.nodes.len()).any(|node| self.servable(node).is_some());
            let next = self
                .nodes
                .iter()
                .flat_map(|node| {
                    TimerFamily::ALL
                        .into_iter()
                        .filter_map(|family| node.driver.clock().deadline(family))
                })
                .map(|at| at.millis())
                .chain(retrieving.then_some(self.now + 1))
                .min()
                .unwrap_or(self.now + 1)
                .max(self.now + 1);
            assert!(
                next <= deadline,
                "no progress within {millis}ms:\n{}",
                self.describe()
            );
            self.advance(next - self.now);
            for node in 0..self.nodes.len() {
                while let Some(index) = self.servable(node) {
                    self.retrieve(node, index);
                }
            }
        }
        panic!("the fair suffix did not finish within {MAX_FAIR_STEPS} steps");
    }

    /// Runs the fair suffix until every node acting for a correct participant resolved
    /// `view` and reported a leader block of at least `finalized` finalized.
    pub(crate) fn run_to(&mut self, millis: u64, view: View, finalized: View) {
        self.run_until(millis, |world| {
            (0..world.nodes.len())
                .filter(|node| world.oracle.is_correct(world.nodes[*node].participant))
                .all(|node| {
                    world.oracle.resolved(node) >= view && world.oracle.finalized(node) >= finalized
                })
        });
    }

    /// Describes every node's progress and queued work, one line per node.
    fn describe(&self) -> String {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let inspection = node.driver.inspect();
                format!(
                    "node {index} ({}): view {}, resolved {}, finalized {}, pending {}, waiting {}, \
                     parked {}, retrievals {}, outbox {}, inbox {}, deferred {}",
                    node.participant,
                    inspection.view(),
                    self.oracle.resolved(index),
                    self.oracle.finalized(index),
                    inspection.pending_artifacts(),
                    inspection.waiting_artifacts(),
                    inspection.parked_updates(),
                    node.retrievals.len(),
                    inspection.outbox_len(),
                    node.inbox.len(),
                    node.deferred.len(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Returns the highest view each node resolved contiguously.
    pub(crate) fn resolved_views(&self) -> Vec<View> {
        (0..self.nodes.len())
            .map(|node| self.oracle.resolved(node))
            .collect()
    }

    /// Checks that every node's durable state equals the state its checkpoint and journal replay
    /// to, draining its barriers first, and that it holds at most `n + 1` headers at any height of
    /// any chain, however many branches its peers' votes name.
    pub(crate) fn check_replay(&mut self) {
        self.settle();
        let per_height = self.committee.codec().participants() + 1;
        for node in &self.nodes {
            let driver = &node.driver;
            let live = driver
                .machine()
                .checkpoint_cut()
                .expect("a settled node has nothing staged");
            let mut replayed = Machine::<Sha256, MinPk>::restore(
                driver.machine().profile().clone(),
                driver.checkpoint().clone(),
            )
            .expect("the checkpoint restores");
            for event in driver.journal() {
                replayed.replay(event.clone()).expect("the journal replays");
            }
            assert_eq!(
                replayed.live_snapshot_for_test(),
                live,
                "node acting for {} does not replay to its live state",
                node.participant
            );
            let headers = &driver.machine().components.chain.headers;
            for chain in (0..node.chains as u32).map(ChainId::new) {
                assert!(
                    headers.widest(chain) <= per_height,
                    "node acting for {} holds more than n + 1 headers at a height of {chain}",
                    node.participant
                );
            }
        }
    }

    /// Runs one adversarial step, or returns `None` once `schedule` is exhausted.
    fn step(&mut self, schedule: &mut impl Schedule) -> Option<()> {
        let node = schedule.choose(self.nodes.len())?;
        match schedule.choose(16)? {
            0..=3 => {
                let length = self.nodes[node].inbox.len();
                if length == 0 {
                    return Some(());
                }
                let index = schedule.choose(length.min(4))?;
                let message = self.nodes[node].inbox.remove(index).expect("in range");
                match schedule.choose(8)? {
                    0 => {}
                    1 => self.nodes[node].inbox.push_back(message),
                    2 => {
                        self.nodes[node].inbox.push_back(message.clone());
                        self.observe(node, message);
                    }
                    _ => self.observe(node, message),
                }
            }
            4..=7 => {
                let length = self.nodes[node].pending.len();
                if length == 0 {
                    return Some(());
                }
                let index = schedule.choose(length.min(4))?;
                let capability = self.nodes[node].pending.remove(index).expect("in range");
                self.execute(node, capability);
            }
            8 => self.append(node),
            9 => self.acknowledge(node),
            10 | 11 => self.poll(node),
            12 => {
                let length = self.nodes[node].retrievals.len();
                if length > 0 {
                    let index = schedule.choose(length)?;
                    self.retrieve(node, index);
                }
            }
            13 | 14 => {
                let millis = schedule.choose(20)? as u64 + 1;
                self.advance(millis);
            }
            _ => {
                if schedule.choose(64)? == 0 {
                    let cut = if schedule.choose(2)? == 0 {
                        Cut::BeforeAppend
                    } else {
                        Cut::BeforeAcknowledge
                    };
                    self.crash(node, cut);
                }
            }
        }
        Some(())
    }

    /// Runs every node's queued work in order until no node can act without time passing.
    fn settle(&mut self) {
        let mut units = 0usize;
        loop {
            let mut progressed = false;
            for node in 0..self.nodes.len() {
                while self.work(node) {
                    progressed = true;
                    units += 1;
                    assert!(
                        units <= MAX_SETTLE_UNITS,
                        "the world did not quiesce without time passing (livelock)"
                    );
                }
            }
            if !progressed {
                return;
            }
        }
    }

    /// Runs one unit of `node`'s queued work in fair order, returning whether there was any.
    fn work(&mut self, node: usize) -> bool {
        let state = &mut self.nodes[node];
        let capacity = state.driver.machine().has_persistence_capacity();
        if let Some(capability) = state.pending.pop_front() {
            self.execute(node, capability);
        } else if !state.journal.is_empty() {
            self.append(node);
        } else if !state.appended.is_empty() {
            self.acknowledge(node);
        } else if !capacity {
            return false;
        } else if let Some(input) = state.deferred.pop_front() {
            self.submit(node, input);
        } else if state.driver.work_remaining() {
            self.poll(node);
        } else if let Some(message) = state.inbox.pop_front() {
            self.observe(node, message);
        } else {
            return false;
        }
        true
    }

    /// Submits `input` to `node`, or holds it while the machine has no persistence capacity
    /// unless it acknowledges a barrier.
    fn submit(&mut self, node: usize, input: Input<MinPk, Digest>) {
        let state = &mut self.nodes[node];
        if !matches!(input, Input::Persisted(_))
            && !state.driver.machine().has_persistence_capacity()
        {
            state.deferred.push_back(input);
            return;
        }
        let step = state
            .driver
            .submit(input)
            .unwrap_or_else(|error| panic!("node {node} rejected an input: {error}"));
        self.absorb(node, step);
    }

    fn absorb(&mut self, node: usize, step: Step<MinPk, Digest>) {
        let (capabilities, activities) = step.into_parts();
        self.absorb_parts(node, capabilities, activities);
    }

    fn absorb_parts(
        &mut self,
        node: usize,
        capabilities: Vec<Capability<MinPk, Digest>>,
        activities: Vec<Activity<MinPk, Digest>>,
    ) {
        for activity in &activities {
            self.oracle.report(node, activity);
        }
        for capability in capabilities {
            match capability {
                // The driver applies timer commands to its clock as it records them.
                Capability::Timer(_) => {}
                // The journal accepts barriers in issuance order, as the voter hands them over.
                Capability::Journal(directive) => {
                    let state = &mut self.nodes[node];
                    state.journal.push_back(directive.job);
                    for artifact in &directive.staged_retention {
                        state.serve(artifact);
                    }
                    state.pending.extend(
                        directive
                            .release_after_enqueue
                            .into_iter()
                            .map(Capability::Released),
                    );
                }
                capability => self.nodes[node].pending.push_back(capability),
            }
        }
    }

    fn poll(&mut self, node: usize) {
        let driver = &self.nodes[node].driver;
        if !driver.work_remaining() || !driver.machine().has_persistence_capacity() {
            return;
        }
        let (capabilities, activities) = self.nodes[node]
            .driver
            .poll_with(NonZeroUsize::MIN)
            .unwrap_or_else(|error| panic!("node {node} failed a poll: {error}"))
            .into_parts();
        self.absorb_parts(node, capabilities, activities);
    }

    fn observe(&mut self, node: usize, message: Message) {
        let cohort = message
            .into_iter()
            .map(|artifact| (*artifact).clone().identify::<Sha256>(&mut Vec::new()))
            .collect();
        self.submit(node, Input::Observe(cohort));
    }

    fn advance(&mut self, millis: u64) {
        self.now += millis;
        for node in 0..self.nodes.len() {
            if let Some(built) = self.nodes[node].built.take() {
                self.nodes[node].last_built = Some(self.now);
                self.submit(node, built);
            }
            for tick in self.nodes[node].driver.elapse(millis) {
                self.submit(node, tick);
            }
        }
    }

    fn append(&mut self, node: usize) {
        if self.crash_at == Some((node, self.nodes[node].barriers, Cut::BeforeAppend))
            && !self.nodes[node].journal.is_empty()
        {
            self.crash_at = None;
            return self.crash(node, Cut::BeforeAppend);
        }
        let state = &mut self.nodes[node];
        let Some(job) = state.journal.pop_front() else {
            return;
        };
        state
            .driver
            .append(&job)
            .unwrap_or_else(|error| panic!("node {node} cannot append: {error}"));
        state.appended.push_back(job);
        state.barriers += 1;
        if self.crash_at == Some((node, state.barriers, Cut::BeforeAcknowledge)) {
            self.crash_at = None;
            self.crash(node, Cut::BeforeAppend);
        }
    }

    fn acknowledge(&mut self, node: usize) {
        let Some(job) = self.nodes[node].appended.pop_front() else {
            return;
        };
        let step = self.nodes[node]
            .driver
            .acknowledge(&job)
            .unwrap_or_else(|error| panic!("node {node} rejected an acknowledgement: {error}"));
        self.absorb(node, step);
    }

    /// Crashes `node` at `cut` and recovers it from its checkpoint and journal.
    pub(crate) fn crash(&mut self, node: usize, cut: Cut) {
        if cut == Cut::BeforeAcknowledge {
            let state = &mut self.nodes[node];
            if let Some(job) = state.journal.pop_front() {
                state
                    .driver
                    .append(&job)
                    .unwrap_or_else(|error| panic!("node {node} cannot append: {error}"));
                state.barriers += 1;
            }
        }
        let state = &mut self.nodes[node];
        state.pending.clear();
        state.journal.clear();
        state.appended.clear();
        state.deferred.clear();
        state.retrievals.clear();
        state.built = None;
        self.oracle.restarted(node);
        let step = self.nodes[node]
            .driver
            .crash_and_restore()
            .unwrap_or_else(|error| panic!("node {node} did not recover: {error}"));
        self.absorb(node, step);
    }

    fn execute(&mut self, node: usize, capability: Capability<MinPk, Digest>) {
        let generation = self.nodes[node].driver.current_generation();
        let input = match capability {
            Capability::Verify(job) => Input::Verified(match self.verification {
                Verification::Real => verify::<Sha256, _, _>(
                    &job,
                    &mut self.rng,
                    &self.committee.verifier,
                    &Sequential,
                ),
                Verification::Symbolic => {
                    super::executors::SymbolicVerifier::new(true).complete(&job)
                }
            }),
            Capability::Quarantine(participants) => {
                return self.oracle.quarantined(node, &participants);
            }
            Capability::Acknowledged { retention } => {
                for artifact in &retention {
                    self.nodes[node].serve(artifact);
                }
                return;
            }
            Capability::Retain(artifact) => return self.nodes[node].serve(&artifact),
            Capability::Retire(_)
            | Capability::Timer(_)
            | Capability::Journal(_)
            | Capability::Chain(_, ChainCommand::Accepted(_))
            | Capability::Resolver(ResolverCommand::SettleHeaders { .. }) => return,
            Capability::Released(job) => self.release(node, &job),
            Capability::Application(AppJob::Build(job)) => {
                let parent = job.parent();
                let salt = [self.nodes[node].salt];
                let body = Sha256::hash(&[parent.digest().as_ref(), &salt]);
                let built =
                    Input::BlockBuilt(BuildCompletion::new(job.issued(), parent, Some(body)));
                let state = &mut self.nodes[node];
                if state.last_built == Some(self.now) {
                    state.built = Some(built);
                    return;
                }
                state.last_built = Some(self.now);
                built
            }
            Capability::Application(AppJob::Custody(job)) => {
                Input::BlockCustodied(CustodyCompletion::new(job.issued(), job.header().clone()))
            }
            Capability::Application(AppJob::Recall(_)) => return,
            Capability::Chain(_, ChainCommand::Validate(block)) => {
                Input::Validated(ValidationCompletion::new(
                    generation,
                    block.header().block_ref::<Sha256>(),
                    BlockValidity::Valid,
                ))
            }
            Capability::Crypto(job) => Input::Crypto(self.aggregate(&job)),
            Capability::Resolver(command) => {
                let retrievals = &mut self.nodes[node].retrievals;
                match command {
                    ResolverCommand::Resolve(job) => retrievals.push(job),
                    ResolverCommand::Cancel(job) | ResolverCommand::Reject(job) => {
                        retrievals.retain(|pending| *pending != job);
                    }
                    ResolverCommand::Prune(view) => {
                        retrievals.retain(|job| job.key().view().is_none_or(|scoped| scoped > view))
                    }
                    ResolverCommand::SettleHeaders { .. } => {}
                }
                return;
            }
        };
        self.submit(node, input);
    }

    /// Signs or publishes one released outbox job and returns its completion.
    fn release(&mut self, node: usize, job: &DurableJob<MinPk, Digest>) -> Input<MinPk, Digest> {
        let participant = self.nodes[node].participant;
        let completion = match job.request() {
            DurableEffect::Sign(effect) => {
                let scheme = &self.committee.signers[usize::from(participant)];
                let artifacts = effect
                    .requests()
                    .iter()
                    .map(|request| {
                        let artifact = request
                            .sign(scheme)
                            .expect("the signer owns the reserved subject");
                        self.oracle.signed(request, &artifact);
                        Arc::new(artifact)
                    })
                    .collect();
                EffectCompletion::signed(job.issued(), artifacts)
            }
            DurableEffect::Publish(publication) => {
                let messages: Vec<Message> = match publication {
                    Publication::Broadcast(artifacts) => artifacts
                        .iter()
                        .map(|artifact| vec![Arc::clone(artifact)])
                        .collect(),
                    Publication::Propose(proposal) => {
                        let mut message = Vec::new();
                        if proposal.attach_parent()
                            && let Some(parent) = proposal.parent().exact()
                        {
                            message.push(Arc::new(Artifact::Vqc((**parent).clone())));
                        }
                        message.push(Arc::new(Artifact::LeaderBlock(
                            (**proposal.block()).clone(),
                        )));
                        vec![message]
                    }
                };
                for message in messages {
                    self.publish(node, message);
                }
                EffectCompletion::delivered(job.issued())
            }
        };
        Input::EffectCompleted(completion)
    }

    /// Sends `message` from `node` to the nodes the router picks.
    fn publish(&mut self, node: usize, message: Message) {
        for artifact in &message {
            self.oracle.published(artifact);
            self.nodes[node].serve(artifact);
        }
        for recipient in self.router.recipients(self.nodes.len(), node, &message) {
            self.nodes[recipient].inbox.push_back(message.clone());
        }
    }

    /// Returns the index of `node`'s first retrieval some peer can answer.
    fn servable(&self, node: usize) -> Option<usize> {
        let retrievals = &self.nodes[node].retrievals;
        (0..retrievals.len()).find(|index| self.server(node, retrievals[*index].key()).is_some())
    }

    /// Returns a node other than `client` that serves `key` to it.
    fn server(&self, client: usize, key: RetrievalKey<Digest>) -> Option<Arc<WorldArtifact>> {
        (0..self.nodes.len())
            .filter(|server| *server != client && self.router.serves(*server, client))
            .find_map(|server| self.nodes[server].served.get(&key).cloned())
    }

    /// Answers `node`'s `index`-th retrieval if some peer serves it.
    fn retrieve(&mut self, node: usize, index: usize) {
        let job = self.nodes[node].retrievals[index];
        let Some(artifact) = self.server(node, job.key()) else {
            return;
        };
        self.nodes[node].retrievals.swap_remove(index);
        let artifact = (*artifact).clone().identify::<Sha256>(&mut Vec::new());
        self.submit(
            node,
            Input::ResolutionCompleted(ResolutionCompletion::new(job, artifact)),
        );
    }

    fn aggregate(&mut self, job: &CryptoJob<MinPk, Digest>) -> CryptoCompletion<MinPk, Digest> {
        let verifier = &self.committee.verifier;
        match job {
            CryptoJob::AggregateVqc(job) => CryptoCompletion::Vqc(Box::new(Aggregated::new(
                job.issued(),
                verifier
                    .assemble_vqc(
                        &mut self.rng,
                        job.parent(),
                        job.votes(),
                        job.paths().to_vec(),
                        SignatureVerification::Preverified,
                        &Sequential,
                    )
                    .expect("the machine selects votes that form a V-QC"),
            ))),
            CryptoJob::AggregateLqc(job) => CryptoCompletion::Lqc(Box::new(Aggregated::new(
                job.issued(),
                verifier
                    .assemble_lqc::<_, Sha256, _>(
                        &mut self.rng,
                        job.leader().clone(),
                        job.votes(),
                        SignatureVerification::Preverified,
                        &Sequential,
                    )
                    .expect("the machine selects votes that form an L-QC"),
            ))),
        }
    }
}

/// Runs a world of six correct nodes on the choices `data` encodes, one per byte, then a fair
/// suffix that must resolve three more views, checking every oracle and replay equivalence.
///
/// Signatures are checked symbolically: every artifact in the world is honestly signed.
pub(crate) fn exercise(data: &[u8]) {
    let mut config = Config::correct(Committee::builder(7, 6).build());
    config.verification = Verification::Symbolic;
    let mut world = World::new(config, Broadcast);
    world.adversarial(&mut Bytes::new(data));
    let furthest = world.resolved_views().into_iter().max().unwrap_or_default();
    let target = View::new(furthest.get() + 3);
    world.run_to(60_000, target, View::new(target.get() - 1));
    world.check_replay();
}

/// Returns the retrieval keys `artifact` answers other than a vote's.
fn keys(artifact: &WorldArtifact) -> Vec<RetrievalKey<Digest>> {
    match artifact {
        Artifact::TransactionBlock(block) => vec![RetrievalKey::Header {
            chain: block.header().chain(),
            digest: block.header().digest::<Sha256>(),
        }],
        Artifact::LeaderBlock(block) => vec![RetrievalKey::LeaderBlock(block.view())],
        Artifact::Update(_) => Vec::new(),
        Artifact::Vqc(certificate) => vec![
            RetrievalKey::Vqc(certificate.id::<Sha256>()),
            RetrievalKey::VqcView(certificate.view()),
        ],
        Artifact::Lqc(certificate) => vec![RetrievalKey::Lqc(certificate.id::<Sha256>())],
        Artifact::Floor(_) => vec![RetrievalKey::LatestFloor],
    }
}

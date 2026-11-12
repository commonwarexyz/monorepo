//! The state-sync driver: five correct identities, one of which joins late.
//!
//! The run starts from an output a trusted dealer deals to the first
//! committee and reshares it among the committees the input schedules, as the
//! reshare restart driver does. Four of the five identities start at the
//! height-zero block. The fifth, the joiner, starts once one of them has
//! applied the height the input selects, which may lie in any phase of any
//! epoch the run is asked to complete. Every engine is a real reshare engine
//! with a real probe that its marshal is attached to, at every start.
//!
//! The joiner enters the way the DKG module documents for a node that state
//! syncs (see [`joiner`](super::joiner)): its probe samples a floor from the
//! others and fetches the description of the floor's epoch, marshal starts
//! from that floor, and the reshare actor and the orchestrator start from the
//! pair. With a floor at or before the midpoint of its epoch the joiner takes
//! part in that epoch's ceremony, and with a later one it follows the epoch
//! and resumes resharing from its final block.
//!
//! The only faults are crashes. The joiner may be crashed on its own clock, a
//! chosen delay after it starts, which lands the crash before the probe has
//! answered, between the floor and its block, or after the sync. A schedule
//! of up to three more restarts over all five identities is drawn from the
//! tape with the sampler of the restart targets, and its first outage is due
//! when the input says, from the joiner's start on, so that it can take down
//! a node the joiner's probe is asking. The environment lays the two out so
//! that at most one identity is down at any moment: an outage that is due
//! while another one lasts starts once that one has ended and its identity
//! has had the time the restart schedule leaves after a restart (see
//! [`environment`]). A restart keeps the identity's storage and its secret
//! store, so a joiner restarted in the middle of its sync resumes from the
//! floor its caller recorded, and one restarted after it recovers through
//! marshal and never syncs again. The links are fixed.
//!
//! The secret stores and the engines' storage are paced, the joiner's
//! included (see [`pacing`](super::pacing)): some of the writes an engine
//! makes shortly before one of its crashes are held, so the crash can fall
//! between two writes the engine makes one after the other. The joiner makes
//! its caller's record, the material of the DKG module's plan, and
//! marshal's floor durable one after the other, and its own crash can fall
//! between any two of them.
//!
//! One identity is impaired at a time. A joiner that has not started is as
//! unavailable as an identity that is down, so it is the impaired identity
//! from the start of the run until its first start has completed: until then
//! no identity is crashed and no write is held. From then on it counts like
//! any other identity, also while it syncs: it is impaired while it is down
//! or has a write held, and the schedule may crash another identity while
//! the joiner's probe discovers. [`RESTARTS_BEFORE_JOIN`] decides whether the
//! first half of this holds. By default it does.
//!
//! The run ends when the schedule has been played out, the latest instance of
//! every engine has entered the epoch after the last one the input selected,
//! and the joiner has completed its sync and entered an epoch after the one
//! of its floor, so that it has committed a boundary of its own. It also ends
//! when an engine stops on its own or the bounded timeout expires. A joiner
//! whose sync never completes is healthy, and such a run ends at the timeout.
//! The invariants of the reshare restart driver are then checked over all
//! five engines, with the joiner held to them from its floor upward, together
//! with I15 to I17 on the steps the joiner's caller took.

use super::{
    DkgStateSyncFuzzInput, EPOCH_LENGTH, Outcome, PublicKey, RESHARE_IDENTITIES,
    RESHARE_RUN_TIMEOUT, TRACKED_PEER_SETS,
    environment::{self, Join, Program, Stack},
    invariants::{
        self, Chain, Instance, Records, Reshare, ReshareCounts, StateSync, Step, SyncCounts,
    },
    joiner::Entry,
    pacing::{PacedCounts, Trace},
    reshare_cluster::{Cluster, ReshareRestartCounts, Session},
    runner::{self, Report},
    signers,
    state_sync_input::Place,
};
use crate::stateful::runner::{LINK, network_with};
use commonware_consensus::types::{Epoch, Height};
use commonware_macros::select;
use commonware_runtime::{Handle, deterministic};
use commonware_utils::channel::mpsc;
use futures::future::{pending, select_all};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Label the driver reports under.
const TARGET: &str = "glue-dkg-state-sync";

/// Whether the restart schedule may take a node down before the joiner has
/// started.
///
/// With `false`, a joiner that has not started counts as the run's impaired
/// identity. The schedule's clock starts when the joiner starts: until then
/// the four identities that started at genesis all run, and every outage of
/// the schedule lands during the joiner's sync or after it. A joiner that
/// has not started is not a crashed node, but it is as unavailable as one,
/// so this keeps at most one identity unavailable at any moment. After the
/// joiner has started, a joiner that is in the committee and has no share
/// yet does not sign, so one crashed member beside it still leaves two of
/// four not signing. A ceremony then almost never fails, and what follows a
/// failed ceremony is almost never reached: a joiner that state syncs into
/// an epoch whose ceremony failed, and the share the DKG module recovers
/// for it from an earlier epoch.
///
/// With `true`, a joiner that has not started does not count. The
/// schedule's clock starts with the run. An outage that is due before the
/// joiner starts crashes a node that started at genesis and brings it back
/// after its downtime, or when the join height is applied if that comes
/// first and the shortest downtime has passed. An outage that names the
/// joiner before it has started does nothing. The outages that are still to
/// come when the joiner starts keep their times. With the joiner in the
/// committee, such an outage leaves two of four members out, which is more
/// than the fault bound of one.
///
/// In both positions no write is held before the joiner has started.
const RESTARTS_BEFORE_JOIN: bool = false;

/// What one state-sync run observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateSyncReport {
    /// Why the run stopped.
    pub outcome: Outcome,
    /// Epochs the run was asked to complete.
    pub asked: u8,
    /// The identity that joined late.
    pub joiner: u8,
    /// Whether the joiner is in the first committee, and so holds a share of
    /// the first output.
    pub member: bool,
    /// The height the others applied before the joiner started.
    pub join_height: u8,
    /// How much each check of the joiner's state sync compared.
    pub sync: SyncCounts,
    /// How much each check of the reshare compared.
    pub counts: ReshareCounts,
    /// Registrations of an epoch the engine holds a share for, each required
    /// to carry that share under I2.
    pub signers: usize,
    /// What the restart schedule did.
    pub restarts: ReshareRestartCounts,
    /// Crashes of another identity that found the joiner's engine running
    /// and not yet entered: its probe was discovering, or its caller was
    /// about to ask it.
    pub discovering: usize,
    /// How the writes the pacing held ended: how many crashes dropped one,
    /// and what each dropped write left behind.
    pub paced: PacedCounts,
    /// How many of the crashes that dropped a held write were the joiner's.
    pub joiner_paced: usize,
    /// Pairs of spans in which two identities were impaired at once. The
    /// joiner's span before its first start is among them unless the
    /// schedule's clock started with the run. There must be none.
    pub overlaps: usize,
    /// The simulated time the run took.
    pub elapsed: Duration,
}

/// The epoch `height` lies in and its place in that epoch, for the report.
fn position(height: Height) -> (Epoch, Place) {
    let length = EPOCH_LENGTH.get();
    (
        Epoch::new(height.get() / length),
        Place::of((height.get() % length) as u8),
    )
}

impl fmt::Display for StateSyncReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (join_epoch, join_phase) = position(Height::new(u64::from(self.join_height)));
        write!(
            f,
            "[{TARGET}] outcome={} asked={} joiner={} member={} join_height={} join_epoch={} \
             join_phase={join_phase:?} starts={} syncs={} entries={} discovered={} \
             resumptions={} completions={} later={}",
            self.outcome,
            self.asked,
            self.joiner,
            self.member,
            self.join_height,
            join_epoch,
            self.sync.starts,
            self.sync.syncs,
            self.sync.entries,
            self.sync.boundaries,
            self.sync.resumptions,
            self.sync.completions,
            self.sync.later,
        )?;
        match self.sync.floor.map(position) {
            Some((epoch, phase)) => write!(f, " floor_epoch={epoch} floor_phase={phase:?}")?,
            None => write!(f, " floor_epoch=none floor_phase=none")?,
        }
        write!(
            f,
            " i16_floors={} i16_descriptions={} i17_blocks={} i17_descriptions={} epochs={} \
             correct_nodes={} boundaries={} successes={} failures={} agreements={} \
             registrations={} signers={} shares={} players={} reconstructions={} \
             continuities={} isolations={} carried={} blocks={} placements={} crashes={} \
             restarts={} dealing={} inclusion={} boundary={} finished={} discovering={} {} \
             joiner_paced_crashes={} overlaps={} elapsed_ms={}",
            self.sync.floors,
            self.sync.pairings,
            self.sync.blocks,
            self.sync.descriptions,
            self.counts.epochs,
            self.counts.correct_nodes,
            self.counts.boundaries,
            self.counts.successes,
            self.counts.failures,
            self.counts.agreements,
            self.counts.registrations,
            self.signers,
            self.counts.shares,
            self.counts.players,
            self.counts.reconstructions,
            self.counts.continuities,
            self.counts.isolations,
            self.counts.carried,
            self.counts.blocks,
            self.counts.placements,
            self.restarts.crashes,
            self.restarts.restarts,
            self.restarts.dealing,
            self.restarts.inclusion,
            self.restarts.boundary,
            self.restarts.finished,
            self.discovering,
            self.paced,
            self.joiner_paced,
            self.overlaps,
            self.elapsed.as_millis(),
        )
    }
}

impl Report for StateSyncReport {
    /// Whether the joiner committed a block above its floor that another
    /// engine committed too, so that I17 compared something.
    fn measured(&self) -> bool {
        self.sync.blocks > 0
    }
}

/// libFuzzer entry point.
pub fn fuzz_dkg_state_sync(input: DkgStateSyncFuzzInput) {
    runner::fuzz(input.raw_bytes.clone(), input, run_dkg_state_sync);
}

/// Run the selected epochs of resharing with one late joiner under one
/// restart schedule and return what the run measured.
///
/// A run is fully determined by its input.
pub fn run_dkg_state_sync(input: DkgStateSyncFuzzInput) -> StateSyncReport {
    execute(input, RESTARTS_BEFORE_JOIN, |late| late).0
}

/// Run `input` over the stack `wrap` makes of the cluster with its late
/// joiner, with the schedule's clock starting with the run if `before_join`
/// and with the joiner otherwise. Returns what the run measured and what its
/// pacing did.
///
/// libFuzzer runs the cluster itself. A test wraps it to plant a fault at the
/// boundary the oracle observes.
fn execute<S: Stack>(
    input: DkgStateSyncFuzzInput,
    before_join: bool,
    wrap: impl FnOnce(Late) -> S,
) -> (StateSyncReport, Trace) {
    let entropy = input.raw_bytes.clone();
    let (asked, joiner, join_height) = (input.session.epochs, input.joiner, input.join_height);
    let member = joiner != input.session.outsider;
    let (observed, panics) = runner::execute(entropy.clone(), |context| {
        run(context, input, entropy, before_join, wrap)
    });

    // Measurement point, outside the runtime so a violation is never caught.
    // No identity is compromised, so no panic is tolerated.
    invariants::check_panics(&panics, &[]);
    let crashes = invariants::check_instances_running(&observed.instances);
    let sync = invariants::check_state_sync(&observed.sync);
    let counts = invariants::check_reshare(&observed.reshare, &observed.blocked);
    let signers = invariants::check_registered_shares(&observed.reshare);
    let report = StateSyncReport {
        outcome: observed.outcome,
        asked,
        joiner,
        member,
        join_height,
        sync,
        counts,
        signers,
        restarts: ReshareRestartCounts {
            crashes,
            ..observed.restarts
        },
        discovering: observed.discovering,
        paced: observed.paced.counts(),
        joiner_paced: observed.paced.interrupted(observed.sync.joiner),
        overlaps: observed.paced.overlaps(),
        elapsed: observed.elapsed,
    };
    (report, observed.paced)
}

/// What a run observed, to be checked once the runtime has stopped.
struct Observations {
    outcome: Outcome,
    /// What every instance of every engine reported, and every share every
    /// secret store held.
    reshare: Reshare,
    /// What every engine reported of the chain, and the steps the joiner's
    /// caller took.
    sync: StateSync,
    /// Every engine instance the run started.
    instances: Vec<Instance>,
    blocked: Vec<(PublicKey, PublicKey)>,
    /// What the driver saw of the schedule. The crashes the oracle counts
    /// are filled in at the measurement point.
    restarts: ReshareRestartCounts,
    /// Crashes of another identity that found the joiner discovering.
    discovering: usize,
    /// What the pacing did.
    paced: Trace,
    elapsed: Duration,
}

/// Resolve once one of the engines `commits` watches has been delivered the
/// block at `height`, or a later one.
async fn applied(commits: &mut [mpsc::UnboundedReceiver<Height>], height: Height) {
    if height == Height::zero() {
        return;
    }
    loop {
        let next = commits.iter_mut().map(|commits| Box::pin(commits.recv()));
        match select_all(next).await.0 {
            Some(committed) if committed >= height => return,
            Some(_) => {}
            None => return pending().await,
        }
    }
}

/// Whether `steps` show the completion of the joiner's sync on its caller's
/// record: the caller reported it, or a later start found it.
///
/// A joiner crashed between recording its completion and reporting it shows
/// the completion at its next start.
fn completed(steps: &[Step]) -> bool {
    steps.iter().any(|step| match step {
        Step::Synced(_) => true,
        Step::Started(start) => start.synced.is_some(),
        Step::Entered(_) => false,
    })
}

/// The cluster of real reshare engines with one identity that joins late.
///
/// The environment starts the identities that start at genesis with the run,
/// and the joiner once one of them has been delivered the join height
/// ([`Stack::joined`]).
struct Late {
    cluster: Cluster,
    /// The identity that joins late.
    joiner: usize,
    /// How the joiner enters the chain.
    entry: Entry,
    /// The height the others apply before the joiner starts.
    height: Height,
    /// The heights the identities that start at genesis are delivered.
    applied: Vec<mpsc::UnboundedReceiver<Height>>,
    /// What the joiner's engine reports.
    joined: Records,
    /// The heights the joiner is delivered and the epochs it registers, as
    /// it does.
    commits: mpsc::UnboundedReceiver<Height>,
    registered: mpsc::UnboundedReceiver<Epoch>,
    /// How many times the joiner's engine has been started, and whether it
    /// is running.
    starts: usize,
    up: bool,
    /// Crashes of another identity that found the joiner discovering, shared
    /// so that it can be read after the run.
    discovering: Arc<AtomicUsize>,
}

impl Late {
    /// `cluster` with the identity at `joiner` joining once another identity
    /// has been delivered the block at `height`.
    fn new(cluster: Cluster, joiner: usize, height: Height) -> Self {
        let applied = cluster
            .nodes
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != joiner)
            .map(|(_, node)| node.records.watch_commits())
            .collect();
        let joined = cluster.nodes[joiner].records.clone();
        Self {
            commits: joined.watch_commits(),
            registered: joined.watch(),
            joined,
            applied,
            cluster,
            joiner,
            entry: Entry::StateSync,
            height,
            starts: 0,
            up: false,
            discovering: Arc::default(),
        }
    }

    /// Whether the joiner's engine is running a start that state syncs and
    /// has not entered: its probe is discovering, or its caller has yet to
    /// read its record and ask the probe.
    fn discovering(&self) -> bool {
        if !self.up {
            return false;
        }
        let steps = self.joined.steps();
        let opened = steps
            .iter()
            .filter(|step| matches!(step, Step::Started(_)))
            .count();
        if opened < self.starts {
            // The caller has not read its record. It syncs unless a
            // completion is on it.
            return !completed(&steps);
        }
        let latest = steps
            .iter()
            .rposition(|step| matches!(step, Step::Started(_)));
        latest.is_some_and(|latest| {
            matches!(&steps[latest], Step::Started(start) if start.syncs)
                && steps.len() == latest + 1
        })
    }

    /// Whether the joiner has completed its sync and registered the scheme of
    /// an epoch after the one of the floor it entered from: it has then
    /// applied a final block of its own, above its floor.
    fn above_floor(&self) -> bool {
        let steps = self.joined.steps();
        let floor = steps.iter().rev().find_map(|step| match step {
            Step::Entered(material) => Some(material.info.epoch),
            _ => None,
        });
        let Some(floor) = floor.filter(|_| completed(&steps)) else {
            return false;
        };
        self.joined
            .registrations()
            .iter()
            .any(|(epoch, _)| *epoch > floor)
    }
}

impl Stack for Late {
    async fn start(&mut self, index: usize) -> Handle<()> {
        // Every engine starts here, at its first start and at every later
        // one. The joiner enters through the probe and state sync at every
        // start, and its caller decides whether that start still syncs.
        let mut config = self.cluster.config(index);
        if index == self.joiner {
            config.entry = self.entry;
            self.starts += 1;
            self.up = true;
        }
        self.cluster.launch(index, config).await
    }

    fn crashing(&mut self, index: usize) {
        if index == self.joiner {
            self.up = false;
        } else if self.discovering() {
            self.discovering.fetch_add(1, Ordering::Relaxed);
        }
        self.cluster.crashing(index);
    }

    async fn settled(&mut self, absent: &[bool]) {
        self.cluster.settled(absent).await;
        if absent[self.joiner] {
            return;
        }
        while !self.above_floor() {
            select! {
                _ = self.commits.recv() => {},
                _ = self.registered.recv() => {},
            }
        }
    }

    async fn joined(&mut self) {
        applied(&mut self.applied, self.height).await;
    }
}

async fn run<S: Stack>(
    mut context: deterministic::Context,
    input: DkgStateSyncFuzzInput,
    entropy: Vec<u8>,
    before_join: bool,
    wrap: impl FnOnce(Late) -> S,
) -> Observations {
    let session = Session::deal(&mut context, signers(RESHARE_IDENTITIES), &input.session);
    let participants = session.participants.clone();
    let joiner = usize::from(input.joiner) % participants.len();

    // The schedule over all nodes, drawn from the tape as the restart targets
    // draw theirs, with its first outage due when the input says, and the
    // joiner's own restart. The links are fixed, so there is no cut.
    let join = Join {
        identity: joiner,
        restart: input
            .joiner_restart
            .map(|restart| (restart.delay(), restart.down())),
        lead: input.first_outage.delay(),
        early: before_join,
    };
    let program = Program::joining(input.restarts, entropy, participants.len(), join);
    let oracle = network_with(&context, &participants, LINK, TRACKED_PEER_SETS).await;

    // The cluster creates every identity's secret store here. The oracle
    // reads what the engines report and hold, whatever a test makes of the
    // cluster.
    let cluster = Cluster::new(&context, oracle.clone(), session).paced(&program);
    let view = cluster.view();
    let genesis = cluster.session.genesis.clone();
    let records: Vec<Records> = cluster
        .nodes
        .iter()
        .map(|node| node.records.clone())
        .collect();
    let late = Late::new(cluster, joiner, Height::new(u64::from(input.join_height)));
    let discovering = late.discovering.clone();

    // The environment starts the identities that start at genesis, starts
    // the joiner once the join height has been applied, and plays the
    // outages.
    let mut stack = wrap(late);
    let played = environment::play(
        &context,
        &oracle,
        &participants,
        LINK,
        program,
        &mut stack,
        RESHARE_RUN_TIMEOUT,
    )
    .await;

    // Every identity is correct, so every engine is in the records.
    let blocked = runner::blocked(&oracle).await;
    let nodes = records
        .iter()
        .enumerate()
        .map(|(engine, records)| Chain::observed(engine, records))
        .collect();
    Observations {
        outcome: played.outcome,
        reshare: view.reshare(),
        sync: StateSync {
            genesis,
            joiner,
            nodes,
        },
        instances: played.instances,
        blocked,
        restarts: view.counts(),
        discovering: discovering.load(Ordering::Relaxed),
        paced: played.paced,
        elapsed: played.elapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        FirstOutage, Info, JoinerRestart, Rotation,
        context::EngineContext,
        environment::DOWNTIME_STEP,
        fixtures::{
            self, OUTSIDER, ROTATE, Retaining, STAY, Sampled, Watched, decode, sample, tape,
        },
        invariants::Startup,
        joiner::Lapse,
        pacing::{Operation, Partition},
        reshare_input::ROTATIONS,
        reshare_restarts_input::SessionControls,
        reshare_stack,
        store::Secrets,
    };
    use commonware_cryptography::{Hasher as _, Sha256, bls12381::primitives::sharing::Mode};
    use commonware_glue::dkg::types::EpochOutcome;
    use commonware_p2p::{Blocker as _, block};
    use commonware_runtime::{Clock as _, Spawner as _, Supervisor as _};
    use commonware_utils::sync::Mutex;
    use std::{collections::BTreeMap, sync::OnceLock, time::SystemTime};

    /// A member of the first committee of every fixed input.
    const MEMBER: u8 = 0;

    /// An input whose schedule over all nodes, if it has one, starts 800
    /// milliseconds after the joiner.
    fn input(
        epochs: u8,
        rotations: [Rotation; ROTATIONS],
        joiner: u8,
        join_height: u8,
        joiner_restart: Option<JoinerRestart>,
        restarts: u8,
        seed: u16,
    ) -> DkgStateSyncFuzzInput {
        DkgStateSyncFuzzInput {
            session: SessionControls {
                epochs,
                sharing_mode: Mode::NonZeroCounter,
                outsider: OUTSIDER,
                rotations,
            },
            joiner,
            join_height,
            joiner_restart,
            restarts,
            first_outage: FirstOutage {
                steps: 10,
                doublings: 3,
            },
            raw_bytes: tape(seed),
        }
    }

    /// A restart of the joiner `steps` times ten milliseconds after it
    /// starts, doubled `doublings` times, with the shortest downtime.
    const fn after(steps: u8, doublings: u8) -> Option<JoinerRestart> {
        Some(JoinerRestart {
            steps,
            doublings,
            downtime: 1,
        })
    }

    /// Run `input` over the cluster with its late joiner, and assert that no
    /// two identities were impaired at once, the joiner before its first
    /// start among them. Returns what the run measured and what its pacing
    /// did.
    fn observed(input: DkgStateSyncFuzzInput) -> (StateSyncReport, Trace) {
        let (report, trace) = execute(input, RESTARTS_BEFORE_JOIN, |late| late);
        println!("{report}");
        assert_eq!(trace.overlaps(), 0, "{:?}", trace.impairments());
        assert_eq!(report.overlaps, 0, "{report}");
        (report, trace)
    }

    /// Assert that the checks of a run were not vacuous: the run played its
    /// schedule out, the joiner completed its sync and committed a boundary
    /// above its floor, and every check of its sync compared something.
    fn assert_synced(report: &StateSyncReport) {
        assert_eq!(report.outcome, Outcome::Completed, "{report}");
        assert!(report.measured(), "{report}");
        let (sync, counts) = (report.sync, report.counts);
        assert_eq!(counts.correct_nodes, 5, "{report}");
        assert_eq!(counts.blocks, 0, "{report}");
        assert!(counts.epochs >= usize::from(report.asked), "{report}");
        assert_eq!(
            counts.successes + counts.failures,
            counts.epochs,
            "{report}"
        );

        // I15: the joiner synced, and its sync completed once. A joiner
        // crashed between recording the completion and reporting it shows it
        // at its next start.
        assert!(sync.starts >= 1, "{report}");
        assert!(sync.completions <= 1, "{report}");
        assert!(sync.completions == 1 || sync.later >= 1, "{report}");
        assert!(sync.entries >= 1, "{report}");

        // I16: every floor it entered from and every description it paired
        // was traced to the nodes that started at genesis.
        assert_eq!(sync.floors, sync.entries, "{report}");
        assert_eq!(sync.pairings, sync.entries, "{report}");

        // I17: marshal delivered it its floor, and it committed blocks and a
        // boundary above it that the others committed too.
        assert!(sync.floor.is_some(), "{report}");
        assert!(sync.blocks > 0, "{report}");
        assert!(sync.descriptions > 0, "{report}");
    }

    /// Run one fixed input and assert that its checks were not vacuous and
    /// that no two identities were impaired at once.
    fn synced(input: DkgStateSyncFuzzInput) -> StateSyncReport {
        let report = observed(input).0;
        assert_synced(&report);
        report
    }

    /// Run `inputs` in order, one at a time, until the run of one `shows`
    /// what a test is about, and return what that run measured (see
    /// [`fixtures::first`]).
    fn first(
        inputs: impl IntoIterator<Item = DkgStateSyncFuzzInput>,
        shows: impl Fn(&StateSyncReport) -> bool + Sync,
    ) -> StateSyncReport {
        fixtures::first(inputs, 1, |input| Some(synced(input)).filter(&shows))
    }

    /// The epoch and the place of the floor the joiner of `report` entered
    /// from.
    fn floor(report: &StateSyncReport) -> (Epoch, Place) {
        position(
            report
                .sync
                .floor
                .expect("the joiner was delivered its floor"),
        )
    }

    /// Runs of two epochs over an unchanging committee, without a crash, in
    /// which `joiner` starts once each of `heights` has been applied.
    fn joining(
        joiner: u8,
        heights: impl IntoIterator<Item = u8>,
    ) -> impl Iterator<Item = DkgStateSyncFuzzInput> {
        heights
            .into_iter()
            .map(move |height| input(2, STAY, joiner, height, None, 0, 1))
    }

    /// The joiner is the identity outside every committee. It syncs from a
    /// floor in the first epoch, whose description is the configured one,
    /// and commits every block from its floor to the end of the run, the
    /// boundaries among them, as the other four do.
    #[test]
    fn outside_joiner_syncs_and_commits_above_its_floor() {
        let report = first(joining(OUTSIDER, 3..=8), |report| {
            floor(report) == (Epoch::zero(), Place::Early)
        });
        assert!(!report.member, "{report}");
        let (sync, counts) = (report.sync, report.counts);
        assert_eq!(
            (sync.starts, sync.syncs, sync.entries, sync.boundaries),
            (1, 1, 1, 0),
            "{report}"
        );
        assert_eq!(
            (sync.resumptions, sync.completions, sync.later),
            (0, 1, 0),
            "{report}"
        );

        // Every block from its floor to the last boundary is compared with
        // four engines, as is each description it commits.
        assert!(sync.blocks >= 4 * 50, "{report}");
        assert_eq!(sync.descriptions, 4 * counts.epochs, "{report}");

        // It is in no committee, so the four members play every ceremony.
        assert_eq!(counts.failures, 0, "{report}");
        assert_eq!(counts.boundaries, 5 * counts.epochs, "{report}");
        assert_eq!(counts.players, 4 * counts.epochs, "{report}");
        assert_eq!(report.signers, 4 * (counts.epochs + 1), "{report}");
    }

    /// The joiner is a member of the first committee and holds a share of
    /// the first output. Its floor is before the midpoint of the first
    /// epoch, so it takes part in that epoch's ceremony, as a dealer and as
    /// a player, and must hold a share of every output the run reshares.
    #[test]
    fn member_that_joins_before_the_midpoint_plays_the_ceremony() {
        let report = first(joining(MEMBER, 3..=8), |report| {
            floor(report) == (Epoch::zero(), Place::Early)
        });
        assert!(report.member, "{report}");
        let counts = report.counts;
        assert_eq!(counts.failures, 0, "{report}");
        assert_eq!(counts.players, 4 * counts.epochs, "{report}");
        assert_eq!(counts.shares, 4 * (counts.epochs + 1), "{report}");

        // It registers the first epoch too, with the share it was dealt.
        assert!(report.signers > 4 * (counts.epochs + 1), "{report}");
    }

    /// A floor at the midpoint still leaves the whole inclusion window to
    /// the joiner, which takes part in the ceremony.
    #[test]
    fn member_that_joins_at_the_midpoint_plays_the_ceremony() {
        let report = first(joining(1, 13..=16), |report| {
            floor(report) == (Epoch::zero(), Place::Midpoint)
        });
        let counts = report.counts;
        assert_eq!(counts.failures, 0, "{report}");
        assert_eq!(counts.players, 4 * counts.epochs, "{report}");
    }

    /// A floor past the midpoint makes the joiner follow the rest of the
    /// epoch. It registers the next epoch from the final block without a
    /// share of the output it did not play for, which I2 does not ask of it,
    /// takes part in the next ceremony, and must hold a share of that one's
    /// output.
    #[test]
    fn member_that_joins_past_the_midpoint_follows_the_epoch() {
        let report = first(joining(1, 15..=20), |report| {
            floor(report) == (Epoch::zero(), Place::Late)
        });
        let counts = report.counts;
        assert_eq!(counts.failures, 0, "{report}");

        // Three players of the second output and all four of every later
        // one.
        assert_eq!(counts.players, 4 * counts.epochs - 1, "{report}");
        assert_eq!(counts.shares, 4 * (counts.epochs + 1) - 1, "{report}");
    }

    /// The join height is the final block of an epoch, and the floor is
    /// that block or a block of the next epoch. Either way the joiner plays
    /// no ceremony it was not there for.
    #[test]
    fn member_that_joins_at_the_final_block_enters_on_either_side_of_it() {
        let mut places = Vec::new();
        for seed in 1..=4 {
            let report = synced(input(2, STAY, 1, 31, None, 0, seed));
            let (epoch, place) = floor(&report);
            let counts = report.counts;
            assert_eq!(counts.failures, 0, "{report}");
            match (epoch.get(), place) {
                // It follows the first epoch from its final block.
                (0, Place::Boundary) => {
                    assert_eq!(report.sync.boundaries, 0, "{report}");
                }
                // It discovers the boundary and enters the second epoch.
                (1, Place::Early) => {
                    assert_eq!(report.sync.boundaries, 1, "{report}");
                }
                other => panic!("the floor is far from the join height: {other:?} {report}"),
            }
            assert_eq!(counts.players, 4 * counts.epochs - 1, "{report}");
            places.push(place);
        }
        println!("{places:?}");
    }

    /// The joiner starts in the second epoch. Its probe fetches the boundary
    /// that leads into that epoch, and the description it pairs with its
    /// floor is the one the others were delivered in that boundary's block.
    /// It was not there for the first ceremony, so it enters the epoch
    /// without a share, plays the second ceremony, and holds a share of
    /// the third output.
    #[test]
    fn joiner_in_a_later_epoch_discovers_its_boundary() {
        let report = first(joining(MEMBER, 36..=44), |report| {
            floor(report) == (Epoch::new(1), Place::Early)
        });
        assert_eq!(report.sync.boundaries, 1, "{report}");
        let counts = report.counts;
        assert_eq!(counts.failures, 0, "{report}");
        assert_eq!(
            report.sync.descriptions,
            4 * (counts.epochs - 1),
            "{report}"
        );
        assert_eq!(counts.players, 4 * counts.epochs - 1, "{report}");

        // Past the midpoint of the second epoch it plays neither ceremony.
        let report = first(joining(MEMBER, 50..=58), |report| {
            floor(report) == (Epoch::new(1), Place::Late)
        });
        assert_eq!(report.sync.boundaries, 1, "{report}");
        let counts = report.counts;
        assert_eq!(counts.players, 4 * counts.epochs - 2, "{report}");

        // The third epoch of a longer run.
        let report = first(
            (66..=74).map(|height| input(3, STAY, OUTSIDER, height, None, 0, 2)),
            |report| floor(report).0 == Epoch::new(2),
        );
        assert_eq!(report.sync.boundaries, 1, "{report}");
        let counts = report.counts;
        assert_eq!(counts.players, 4 * counts.epochs, "{report}");
    }

    /// The join height is the last height the run was asked for. The chain
    /// goes on until the joiner has committed a boundary above its floor.
    #[test]
    fn joiner_at_the_last_height_commits_the_next_boundary() {
        let report = synced(input(1, STAY, OUTSIDER, 31, None, 0, 1));
        assert!(report.counts.epochs >= 1, "{report}");
        let report = synced(input(2, STAY, MEMBER, 63, None, 0, 1));
        assert!(report.counts.epochs >= 2, "{report}");
    }

    /// The joiner starts with the run, before the chain has a block. Its
    /// probe asks again until the others have finalized one.
    #[test]
    fn joiner_that_starts_with_the_run_waits_for_a_floor() {
        let report = synced(input(1, STAY, MEMBER, 0, None, 0, 1));
        assert_eq!(floor(&report).0, Epoch::zero(), "{report}");
        assert_eq!(report.sync.boundaries, 0, "{report}");
    }

    /// The joiner of a first-epoch run, restarted once: at every delay from
    /// none to 150 milliseconds after it starts, and at a few later ones,
    /// under three tapes, which hold different writes of the joiner before
    /// its crash. Each run is given with what its pacing did.
    fn restarted() -> &'static [(StateSyncReport, Trace)] {
        static RUNS: OnceLock<Vec<(StateSyncReport, Trace)>> = OnceLock::new();
        RUNS.get_or_init(|| {
            let near = (0..=15).map(|steps| after(steps, 0));
            let far = [(5, 2), (10, 2), (15, 2), (10, 4), (15, 4)]
                .into_iter()
                .map(|(steps, doublings)| after(steps, doublings));
            let restarts: Vec<_> = near.chain(far).collect();
            (1..=3u16)
                .flat_map(|seed| restarts.iter().map(move |restart| (seed, *restart)))
                .map(|(seed, restart)| {
                    let (report, trace) = observed(input(1, STAY, MEMBER, 5, restart, 0, seed));
                    assert_synced(&report);
                    assert_eq!(report.restarts.crashes, 1, "{report}");
                    assert_eq!(report.restarts.restarts, 1, "{report}");
                    (report, trace)
                })
                .collect()
        })
    }

    /// The joiner is crashed after its caller recorded a floor and before
    /// the completion of its sync is on record. The engine that comes back
    /// finds the floor, hands it to its probe, enters from a floor that is
    /// not earlier, and completes the sync.
    #[test]
    fn joiner_restarted_in_the_middle_of_its_sync_resumes() {
        let resumed: Vec<_> = restarted()
            .iter()
            .map(|(report, _)| report)
            .filter(|report| report.sync.resumptions > 0)
            .collect();
        assert!(!resumed.is_empty(), "no restart landed inside the sync");
        for report in &resumed {
            let sync = report.sync;
            assert_eq!((sync.starts, sync.syncs), (2, 2), "{report}");
            assert_eq!((sync.resumptions, sync.later), (1, 0), "{report}");
            assert_eq!(sync.completions, 1, "{report}");

            // Every floor it entered from was traced to the nodes that
            // started at genesis. A first start that was crashed between
            // recording its floor and reporting it reported no entry.
            assert!((1..=2).contains(&sync.entries), "{report}");
            assert_eq!((sync.floors, sync.pairings), (sync.entries, sync.entries));
        }

        // Some of them entered at both starts.
        assert!(resumed.iter().any(|report| report.sync.entries == 2));
    }

    /// The joiner is crashed after its sync completed. The engine that
    /// comes back finds the completion, does not sync again although it is
    /// asked to, and recovers through marshal.
    #[test]
    fn joiner_restarted_after_its_sync_does_not_sync_again() {
        let later: Vec<_> = restarted()
            .iter()
            .map(|(report, _)| report)
            .filter(|report| report.sync.later > 0)
            .collect();
        assert!(!later.is_empty(), "no restart landed after the sync");
        for report in later {
            let sync = report.sync;
            assert_eq!(
                (sync.starts, sync.syncs, sync.entries),
                (2, 1, 1),
                "{report}"
            );
            assert_eq!((sync.resumptions, sync.later), (0, 1), "{report}");
        }
    }

    /// The joiner is crashed before its caller recorded a floor: while its
    /// probe was still asking, or before its caller had read its record.
    /// The engine that comes back syncs afresh.
    #[test]
    fn joiner_restarted_before_its_floor_syncs_afresh() {
        let afresh: Vec<_> = restarted()
            .iter()
            .map(|(report, _)| report)
            .filter(|report| report.sync.resumptions == 0 && report.sync.later == 0)
            .collect();
        assert!(!afresh.is_empty(), "no restart landed before the floor");
        for report in &afresh {
            let sync = report.sync;
            assert_eq!(sync.syncs, sync.starts, "{report}");
            assert_eq!((sync.entries, sync.completions), (1, 1), "{report}");
        }

        // Some of them found the first engine's caller at work, and some
        // were crashed before it had read its record.
        assert!(afresh.iter().any(|report| report.sync.starts == 2));
        assert!(afresh.iter().any(|report| report.sync.starts == 1));
    }

    /// The joiner's own crash is one the pacing knows: writes the joiner
    /// makes shortly before it are held, and the crash drops them. Among
    /// them are writes of what the joiner makes durable while it syncs: its
    /// caller's record, the DKG module's material, and marshal's floor.
    #[test]
    fn joiner_is_crashed_between_the_writes_of_its_sync() {
        let joiner = usize::from(MEMBER);
        let mut dropped = BTreeMap::new();
        let mut crashes = 0;
        for (report, trace) in restarted() {
            assert_eq!(report.joiner_paced, report.paced.crashes, "{report}");
            crashes += report.joiner_paced;
            for (operation, _) in trace.dropped(joiner) {
                if let Operation::Blob(partition, _) = operation {
                    *dropped.entry(partition).or_insert(0usize) += 1;
                }
            }
        }
        println!("{crashes} {dropped:?}");
        assert!(crashes > 0);
        assert!(dropped.contains_key(&Partition::Chain), "{dropped:?}");
        assert!(
            dropped.contains_key(&Partition::Ledger) || dropped.contains_key(&Partition::StateSync),
            "{dropped:?}"
        );
    }

    /// A sync interrupted in a later epoch resumes through the probe, which
    /// fetches the boundary again.
    ///
    /// How long after its start the joiner has a floor and no completion
    /// depends on how long its probe and its marshal wait for their peers,
    /// so the restart is looked for among delays of up to 600 milliseconds.
    #[test]
    fn interrupted_sync_in_a_later_epoch_discovers_its_boundary_again() {
        let inputs = (0..=2u8).flat_map(|doublings| {
            (1..=4u16).flat_map(move |seed| {
                (4..=15).map(move |steps| input(2, STAY, 2, 40, after(steps, doublings), 0, seed))
            })
        });
        let report = fixtures::first(inputs, 4, |input| {
            let report = synced(input);
            let sync = report.sync;
            (sync.resumptions > 0 && sync.entries == 2 && floor(&report).0 > Epoch::zero())
                .then_some(report)
        });
        assert_eq!(report.sync.boundaries, 2, "{report}");
    }

    /// The first outage of the schedule is due with the joiner's start or
    /// shortly after it, and takes down a node the joiner's probe is asking.
    /// The probe gets its floor from the others, or asks again.
    #[test]
    fn outage_during_the_discovery_takes_down_a_node_the_probe_asks() {
        let inputs = (0..=4u8).flat_map(|steps| {
            (0..6u16).map(move |seed| {
                let mut input = input(1, STAY, MEMBER, 5, None, 1, seed);
                input.first_outage = FirstOutage {
                    steps,
                    doublings: 0,
                };
                input
            })
        });
        let report = first(inputs, |report| report.discovering > 0);
        assert_eq!(report.restarts.crashes, 1, "{report}");
        assert_eq!(report.sync.completions, 1, "{report}");
    }

    /// Full schedules over rotating committees, with the joiner's own
    /// restart: every outage is played, and the crashes land on the joiner
    /// and on the others, before the joiner has a floor and after its sync,
    /// in every window of the epochs it runs through.
    #[test]
    fn restarts_of_every_node_around_the_sync_hold_invariants() {
        let (mut again, mut later) = (0, 0);
        let mut landed = ReshareRestartCounts::default();
        let mut paced = PacedCounts::default();
        for seed in 0..8u16 {
            let restart = Some(JoinerRestart {
                steps: 5 + seed as u8,
                doublings: (seed % 3) as u8,
                downtime: 2,
            });
            let joiner = (seed % 5) as u8;
            let join_height = 4 + 11 * seed as u8;
            let report = synced(input(3, ROTATE, joiner, join_height, restart, 3, seed));
            assert_eq!(report.restarts.crashes, 4, "{report}");
            assert_eq!(report.restarts.restarts, 4, "{report}");
            again += report.sync.syncs - 1;
            later += report.sync.later;
            paced += report.paced;
            landed.dealing += report.restarts.dealing;
            landed.inclusion += report.restarts.inclusion;
            landed.boundary += report.restarts.boundary;
            landed.finished += report.restarts.finished;
        }
        assert!(again > 0);
        assert!(later > 0);
        assert!(landed.dealing > 0, "{landed:?}");
        assert!(landed.inclusion > 0, "{landed:?}");
        assert!(landed.boundary > 0, "{landed:?}");
        assert!(landed.finished > 0, "{landed:?}");

        // Some of the crashes fell inside a held write.
        assert!(paced.crashes > 0, "{paced:?}");
        assert!(paced.before + paced.durable > 0, "{paced:?}");
    }

    /// Any of the five identities may join late, whichever of them is
    /// outside the first committee.
    #[test]
    fn every_identity_may_join() {
        for joiner in 0..RESHARE_IDENTITIES as u8 {
            for outsider in [OUTSIDER, 1] {
                let mut input = input(1, ROTATE, joiner, 8, None, 1, 3);
                input.session.outsider = outsider;
                let report = synced(input);
                assert_eq!(report.member, joiner != outsider, "{report}");
            }
        }
    }

    #[test]
    fn roots_of_unity_runs() {
        let mut input = input(2, ROTATE, 2, 20, after(9, 0), 2, 9);
        input.session.sharing_mode = Mode::RootsOfUnity;
        synced(input);
    }

    /// What a partition holds decides how often the pacing holds its writes
    /// and how the report counts them, and is told by the partition's name.
    /// Every engine opens the partitions a reshare engine opens, the joiner
    /// opens its caller's record as well, and none opens one the pacing does
    /// not know.
    ///
    /// An engine that started at genesis opens all of them in any run. What
    /// the joiner opens beside its record, the material of its sync, and
    /// marshal's stores depends on where its floor falls: it writes to its
    /// journal once it takes part in a ceremony, and its orchestrator opens
    /// a Simplex journal once it runs an epoch, which a joiner whose run
    /// ends at the first boundary above its floor may not have done. So the
    /// joiner is held to that much in every run, and to all of it in one.
    #[test]
    fn engines_open_the_partitions_the_pacing_knows() {
        let joiner = 3u8;
        let reshare = [
            Partition::Journal,
            Partition::StateSync,
            Partition::Consensus,
            Partition::Chain,
        ];
        let mut everything = false;
        for height in [5, 37, 60] {
            let (report, trace) = observed(input(2, ROTATE, joiner, height, after(9, 0), 1, 21));
            let joined = usize::from(joiner);
            for engine in (0..RESHARE_IDENTITIES as usize).filter(|engine| *engine != joined) {
                assert_eq!(trace.opened(engine), reshare, "engine {engine}: {report}");
            }
            let opened = trace.opened(joined);
            for partition in [Partition::StateSync, Partition::Ledger, Partition::Chain] {
                assert!(opened.contains(&partition), "{opened:?}: {report}");
            }
            let optional: Vec<_> = opened
                .iter()
                .filter(|partition| !reshare.contains(partition))
                .collect();
            assert_eq!(optional, [&Partition::Ledger], "{opened:?}: {report}");
            everything |= opened.len() == reshare.len() + 1;
        }
        assert!(everything, "no joiner of the range opened every partition");
    }

    /// A joiner that has not started is the run's impaired identity: until
    /// its first start has completed no identity is crashed and no write is
    /// held, and its span is on the trace the overlaps are counted from.
    #[test]
    fn nothing_is_impaired_before_the_joiner_starts() {
        for seed in 0..4u16 {
            let joiner = (seed % 5) as u8;
            let mut input = input(2, ROTATE, joiner, 40, after(3, 0), 3, seed);
            input.first_outage = FirstOutage {
                steps: seed as u8,
                doublings: 0,
            };
            let (report, trace) = observed(input);
            assert!(report.restarts.crashes > 0, "{report}");
            let impairments = trace.impairments();
            let absence = &impairments[0];
            assert_eq!(absence.engine, usize::from(joiner), "{impairments:?}");
            assert_eq!(absence.from, Duration::ZERO, "{impairments:?}");
            let started = absence.until.expect("the joiner started");
            assert!(started > Duration::from_secs(1), "{impairments:?}");
            for later in &impairments[1..] {
                assert!(later.from >= started, "{impairments:?}");
            }
        }
    }

    /// The starts and the crashes the environment makes of a run, each with
    /// the time it was made at, and the time each start completed at.
    #[derive(Clone, Default)]
    struct Log {
        starts: Arc<Mutex<Vec<(SystemTime, usize)>>>,
        started: Arc<Mutex<Vec<(SystemTime, usize)>>>,
        crashes: Arc<Mutex<Vec<(SystemTime, usize)>>>,
    }

    /// The cluster with its late joiner, with every start and crash logged.
    struct Logged {
        late: Late,
        log: Log,
    }

    impl Stack for Logged {
        async fn start(&mut self, index: usize) -> Handle<()> {
            let now = self.late.cluster.context.current();
            self.log.starts.lock().push((now, index));
            let handle = self.late.start(index).await;
            let now = self.late.cluster.context.current();
            self.log.started.lock().push((now, index));
            handle
        }

        fn crashing(&mut self, index: usize) {
            let now = self.late.cluster.context.current();
            self.log.crashes.lock().push((now, index));
            self.late.crashing(index);
        }

        async fn settled(&mut self, absent: &[bool]) {
            self.late.settled(absent).await;
        }

        async fn joined(&mut self) {
            self.late.joined().await;
        }
    }

    /// What the environment did around the joiner's first start.
    struct Around {
        report: StateSyncReport,
        trace: Trace,
        /// The crashes made before the joiner first started, and all of
        /// them.
        before: usize,
        crashes: usize,
        /// The shortest time an identity crashed before the joiner started
        /// stayed down.
        shortest: Option<Duration>,
    }

    /// Run `input` with the schedule's clock starting with the run if
    /// `before_join`, and return what the environment did around the
    /// joiner's first start.
    fn around(input: DkgStateSyncFuzzInput, before_join: bool) -> Around {
        let joiner = usize::from(input.joiner);
        let log = Log::default();
        let (report, trace) = execute(input, before_join, |late| Logged {
            late,
            log: log.clone(),
        });
        println!("{report}");
        assert_synced(&report);
        assert_eq!(trace.overlaps(), 0, "{:?}", trace.impairments());
        let (starts, crashes) = (log.starts.lock().clone(), log.crashes.lock().clone());
        let joined = starts
            .iter()
            .find(|(_, index)| *index == joiner)
            .expect("the joiner started")
            .0;

        // Every identity that started at genesis is running when the joiner
        // starts: each crash before it is followed by a start before it.
        let before: Vec<_> = crashes.iter().filter(|(at, _)| *at <= joined).collect();
        let shortest = before
            .iter()
            .map(|(crashed, victim)| {
                let back = starts
                    .iter()
                    .find(|(at, index)| index == victim && at >= crashed)
                    .expect("an identity crashed before the joiner starts comes back")
                    .0;
                assert!(back <= joined, "{report}");
                back.duration_since(*crashed)
                    .expect("simulated time does not run backwards")
            })
            .min();
        Around {
            report,
            trace,
            before: before.len(),
            crashes: crashes.len(),
            shortest,
        }
    }

    /// Inputs whose schedule over all nodes starts with the clock and whose
    /// joiner starts late in a run of two epochs.
    fn scheduled(seeds: std::ops::Range<u16>) -> impl Iterator<Item = DkgStateSyncFuzzInput> {
        seeds.map(|seed| {
            let mut input = input(2, STAY, MEMBER, 60, None, 3, seed);
            input.first_outage = FirstOutage {
                steps: 10,
                doublings: 0,
            };
            input
        })
    }

    /// With the switch off, every outage of the schedule is played after the
    /// joiner has started.
    #[test]
    fn schedule_clock_starts_with_the_joiner_by_default() {
        for input in scheduled(0..3) {
            let around = around(input, false);
            let report = around.report;
            assert_eq!(around.before, 0, "{report}");
            assert_eq!(around.crashes, 3, "{report}");
            assert_eq!(report.restarts.crashes, 3, "{report}");
        }
    }

    /// With the switch on, the schedule's clock starts with the run: an
    /// outage that is due before the join height is applied takes a node
    /// down while the joiner is still to come, and brings it back before
    /// the joiner starts, after the shortest downtime at least. The
    /// joiner's absence is then no impairment, so the trace has no overlap.
    #[test]
    fn schedule_clock_starts_with_the_run_when_the_switch_is_on() {
        let played = scheduled(0..8)
            .map(|input| around(input, true))
            .find(|around| around.before > 0)
            .expect("no schedule of the range has an outage before the join");
        let report = played.report;
        assert!(played.shortest >= Some(DOWNTIME_STEP), "{report}");
        assert_eq!(report.restarts.crashes, played.crashes, "{report}");
        let joiner = usize::from(MEMBER);
        assert!(
            played
                .trace
                .impairments()
                .iter()
                .all(|impairment| impairment.engine != joiner || impairment.from > Duration::ZERO),
            "{report}"
        );
    }

    /// With the switch on, an outage that names the joiner before it has
    /// started does nothing, and the rest of the schedule is played.
    #[test]
    fn outage_of_a_joiner_that_has_not_started_is_skipped() {
        let skipped = scheduled(0..24)
            .map(|input| around(input, true))
            .find(|around| around.crashes < 3)
            .expect("no schedule of the range names the joiner before it starts");
        let report = skipped.report;
        assert_eq!(report.restarts.crashes, skipped.crashes, "{report}");
        assert_eq!(report.restarts.restarts, skipped.crashes, "{report}");
    }

    /// With the switch on, an identity that is down when the join height is
    /// applied comes back then, so that the joiner starts among four running
    /// engines, and it has been down for the shortest downtime at least.
    #[test]
    fn outage_before_the_join_ends_when_the_joiner_starts() {
        // The joiner is in no committee, so the other three members carry
        // the chain to the join height while one is down. The outage is due
        // 50 milliseconds before the join height is applied, give or take.
        let inputs = (0..12u16).flat_map(|seed| {
            (10..=15u8).map(move |steps| {
                let mut input = input(1, STAY, OUTSIDER, 20, None, 1, seed);
                input.first_outage = FirstOutage {
                    steps,
                    doublings: 3,
                };
                input
            })
        });
        let cut_short = inputs
            .map(|input| {
                let schedule = Program::joining(
                    input.restarts,
                    input.raw_bytes.clone(),
                    RESHARE_IDENTITIES as usize,
                    Join {
                        identity: usize::from(input.joiner),
                        restart: None,
                        lead: input.first_outage.delay(),
                        early: true,
                    },
                )
                .outages()
                .0;
                (schedule[0], around(input, true))
            })
            .find(|(outage, around)| {
                around
                    .shortest
                    .is_some_and(|shortest| shortest < outage.downtime)
            })
            .expect("no outage of the range is cut short by the join");
        let (outage, around) = cut_short;
        let report = around.report;
        assert_eq!(around.before, 1, "{report}");
        assert!(
            around.shortest >= Some(DOWNTIME_STEP),
            "{outage:?} {report}"
        );
        assert_eq!(report.restarts.crashes, 1, "{report}");
        assert_eq!(report.restarts.restarts, 1, "{report}");
    }

    /// Sampled inputs run with the switch on hold the invariants too.
    #[test]
    fn sampled_inputs_run_with_the_switch_on() {
        let runs = sample::each(12, |bytes| execute(decode(bytes), true, |late| late).0);
        assert!(runs.iter().any(|report| report.restarts.crashes > 0));
        assert!(runs.iter().all(|report| report.overlaps == 0));
    }

    /// Inputs decoded the way libFuzzer's are, through the entry point it
    /// calls.
    #[test]
    fn decoded_inputs_run_through_the_entry_point() {
        for bytes in [&[][..], &[0x5a], &[0x01, 0x02, 0x03], &[0xff; 24]] {
            let input: DkgStateSyncFuzzInput = decode(bytes);
            fuzz_dkg_state_sync(input.clone());
            let report = observed(input).0;
            println!("{bytes:?}: {report}");
            assert_eq!(report.counts.correct_nodes, 5, "{report}");
            assert!(report.sync.starts > 0, "{report}");
        }
    }

    /// I10: a replayed input measures the same thing, down to the simulated
    /// time it took and the writes its pacing held.
    #[test]
    fn replay_is_reproducible() {
        let run = || observed(input(2, ROTATE, 3, 37, after(9, 0), 3, 21));
        assert_eq!(run(), run());
    }

    #[test]
    fn report_names_where_the_joiner_entered() {
        let report = first(joining(MEMBER, 50..=58), |report| {
            floor(report) == (Epoch::new(1), Place::Late)
        });
        let rendered = report.to_string();
        assert!(rendered.starts_with("[glue-dkg-state-sync] outcome=completed"));
        for field in [
            "joiner=0 member=true join_height=5",
            "join_epoch=1 join_phase=",
            "syncs=1 entries=1 discovered=1 resumptions=0 completions=1 later=0",
            "floor_epoch=1 floor_phase=Late",
            "i16_floors=1 i16_descriptions=1",
            "discovering=0 paced_crashes=0",
            "joiner_paced_crashes=0 overlaps=0",
        ] {
            assert!(rendered.contains(field), "{rendered}");
        }
    }

    /// What a sample of decoded inputs came to, summed over its runs.
    #[derive(Debug)]
    struct Sample {
        sums: fixtures::Sample,
        /// Crashes of another identity that found the joiner discovering.
        discovering: usize,
        joiner_paced: usize,
    }

    /// Run `count` sampled inputs, decoded the way libFuzzer's are, with the
    /// schedule's clock starting with the run if `before_join`, and sum what
    /// they came to. Every run is checked as libFuzzer's are, and its report
    /// is printed.
    fn sampled(count: usize, before_join: bool) -> Sample {
        let runs = sample::each(count, |bytes| {
            let (report, trace) = execute(decode(bytes), before_join, |late| late);
            (report, trace.overlaps())
        });
        let sample = Sample {
            discovering: runs.iter().map(|(report, _)| report.discovering).sum(),
            joiner_paced: runs.iter().map(|(report, _)| report.joiner_paced).sum(),
            sums: fixtures::Sample::of(runs.into_iter().map(|(report, overlaps)| {
                println!("{report}");
                Sampled {
                    outcome: report.outcome,
                    failed: report.counts.failures > 0,
                    crashes: report.restarts.crashes,
                    paced: report.paced,
                    overlaps,
                }
            })),
        };
        println!("{sample:?}");
        sample
    }

    /// Whatever the input, no two identities are impaired at once, the
    /// joiner before its first start among them.
    #[test]
    fn sampled_inputs_impair_one_identity_at_a_time() {
        let sample = sampled(16, RESTARTS_BEFORE_JOIN);
        assert_eq!(sample.sums.overlapping, Vec::<usize>::new());
        assert!(sample.sums.crashes > 0, "{sample:?}");
    }

    /// The same over a sample large enough to hold the crashes that drop a
    /// held write of the joiner and the outages that land in its discovery.
    /// `SAMPLE` names the number of inputs, and `SAMPLE_BEFORE_JOIN` runs
    /// them with the switch on.
    #[test]
    #[ignore = "runs 1,500 inputs"]
    fn large_sample_impairs_one_identity_at_a_time() {
        let count = std::env::var("SAMPLE").map_or(1_500, |count| {
            count.parse().expect("SAMPLE is a number of inputs")
        });
        let before_join = std::env::var_os("SAMPLE_BEFORE_JOIN").is_some();
        let sample = sampled(count, before_join || RESTARTS_BEFORE_JOIN);
        assert_eq!(sample.sums.overlapping, Vec::<usize>::new());
        assert!(sample.sums.paced.crashes > 0, "{sample:?}");
        assert!(sample.joiner_paced > 0, "{sample:?}");
        assert!(sample.discovering > 0, "{sample:?}");
    }

    /// Lists, for each sampled input, when the first outage of its schedule
    /// is due after the joiner starts, as the tape alone draws it and as
    /// the input does, and whether it names the joiner.
    #[test]
    #[ignore = "a listing of the schedules of sampled inputs"]
    fn survey_first_outages() {
        let count = std::env::var("SAMPLE").map_or(4_000, |count| {
            count.parse().expect("SAMPLE is a number of inputs")
        });
        let lines = sample::each(count, |bytes| {
            let input: DkgStateSyncFuzzInput = decode(bytes);
            let identities = RESHARE_IDENTITIES as usize;
            let join = Join {
                identity: usize::from(input.joiner),
                restart: None,
                lead: input.first_outage.delay(),
                early: false,
            };
            let drawn = environment::schedule(input.restarts, &input.raw_bytes, identities)
                .first()
                .map(|first| first.at.as_millis());
            let program =
                Program::joining(input.restarts, input.raw_bytes.clone(), identities, join);
            let first = program.outages().0.first().copied();
            format!(
                "FIRST restarts={} tape_ms={} input_ms={} joiner={} own_ms={} join_place={:?}",
                input.restarts,
                drawn.map_or("none".to_string(), |at| at.to_string()),
                first.map_or("none".to_string(), |first| first.at.as_millis().to_string()),
                first.is_some_and(|first| first.victim == usize::from(input.joiner)),
                input
                    .joiner_restart
                    .map_or("none".to_string(), |restart| restart
                        .delay()
                        .as_millis()
                        .to_string()),
                position(Height::new(u64::from(input.join_height))).1,
            )
        });
        for line in lines {
            println!("{line}");
        }
    }

    /// Lists, for each sampled input with an outage, how long after a restart
    /// the next crash comes, as the environment lays the outages out and as
    /// it plays them, and the epochs the joiner entered through state sync
    /// after it had registered them. `SAMPLE` names the number of inputs.
    ///
    /// A line gives the distance from each restart that is due to the crash
    /// due after it, the distance from the joiner's start to the first crash
    /// due, and for each crash played after another the distance from the
    /// restart completed before it, marked if the crash was brought forward.
    #[test]
    #[ignore = "a listing of the outages of sampled inputs"]
    fn survey_outages() {
        let count = std::env::var("SAMPLE").map_or(3_000, |count| {
            count.parse().expect("SAMPLE is a number of inputs")
        });
        let millis = |duration: Duration| duration.as_millis();
        let lines = sample::each(count, |bytes| {
            let input: DkgStateSyncFuzzInput = decode(bytes);
            let identities = RESHARE_IDENTITIES as usize;
            let join = Join {
                identity: usize::from(input.joiner),
                restart: input
                    .joiner_restart
                    .map(|restart| (restart.delay(), restart.down())),
                lead: input.first_outage.delay(),
                early: false,
            };
            let program =
                Program::joining(input.restarts, input.raw_bytes.clone(), identities, join);
            let joiner = usize::from(input.joiner);
            let log = Log::default();
            let mut joined = None;
            let (report, trace) = execute(input, false, |late| {
                joined = Some(late.joined.clone());
                Logged {
                    late,
                    log: log.clone(),
                }
            });
            let joined = joined.expect("the cluster was wrapped");
            let (starts, started) = (log.starts.lock().clone(), log.started.lock().clone());
            let crashes = log.crashes.lock().clone();
            let since = |later: SystemTime, earlier: SystemTime| {
                later
                    .duration_since(earlier)
                    .expect("simulated time does not run backwards")
            };

            // The outages as they were laid out when the joiner started.
            let origin = starts[0].0;
            let Some(arrived) = starts.iter().find(|(_, index)| *index == joiner) else {
                return format!("OUTAGES unjoined {report}");
            };
            let laid = program.laid_out(since(arrived.0, origin));
            let due: Vec<_> = laid
                .windows(2)
                .map(|pair| millis(pair[1].at - (pair[0].at + pair[0].downtime)))
                .collect();
            let first_due = laid
                .first()
                .map(|first| millis(first.at - since(arrived.0, origin)));

            // The crashes as they were played: each after the restart that
            // completed before it, or after the joiner's first start.
            let mut played = Vec::new();
            let mut first_played = None;
            for (position, (at, _)) in crashes.iter().enumerate() {
                let forward = since(*at, origin) < laid[position].at;
                if position == 0 {
                    let up = started
                        .iter()
                        .find(|(_, index)| *index == joiner)
                        .expect("the joiner started");
                    first_played = Some((millis(since(*at, up.0)), forward));
                    continue;
                }
                let (crashed, victim) = crashes[position - 1];
                let back = started
                    .iter()
                    .find(|(up, index)| *index == victim && *up >= crashed)
                    .expect("a crashed identity comes back before the next crash");
                played.push((millis(since(*at, back.0)), forward));
            }

            // The epochs every entry of the joiner names, whatever it had
            // registered, and those it is excused.
            let commits = joined.commits();
            let mut entered = std::collections::BTreeSet::new();
            for step in joined.steps() {
                let Step::Entered(material) = step else {
                    continue;
                };
                entered.insert(material.info.epoch);
                let followed = commits.iter().any(|(height, digest)| {
                    *digest == material.digest
                        && matches!(position(*height).1, Place::Late | Place::Boundary)
                });
                if followed {
                    entered.insert(material.info.epoch.next());
                }
            }
            let excused = joined.unplayed();
            let played_for: Vec<_> = entered
                .iter()
                .filter(|epoch| !excused.contains(epoch))
                .collect();
            format!(
                "OUTAGES due={due:?} first_due={first_due:?} played={played:?} \
                 first_played={first_played:?} overlaps={} entered={} played_for={played_for:?} \
                 {report}",
                trace.overlaps(),
                entered.len(),
            )
        });
        for line in lines {
            println!("{line}");
        }
    }

    /// A fault a negative control plants at the boundary the oracle
    /// observes.
    #[derive(Clone, Copy)]
    enum Plant {
        /// Close the channels of this identity's engine as soon as it has
        /// been started, so that the engine ends on its own.
        Sever(usize),
        /// Panic in a task of this identity's engine.
        EnginePanic(usize),
        /// Panic in the harness, on its root task.
        HarnessPanic,
        /// Have the joiner's caller report a start that chose state sync
        /// with the completed sync on its record.
        Again,
        /// Have the joiner's caller report a start that found no record of
        /// the completed sync.
        Forgotten,
        /// Have the joiner report, at the first height, a block the others
        /// did not commit there.
        Fork,
        /// Have the joiner report a second description of the newest epoch
        /// it was delivered, with the other outcome.
        Redescribed,
        /// Hand the joiner's engine a secret store the oracle does not
        /// read, so that no share it stores is on record.
        Unrecorded,
        /// Have the first identity block the second.
        Block(usize, usize),
    }

    /// The cluster with its late joiner and one fault planted.
    struct Planted {
        late: Late,
        plant: Plant,
        /// Whether the fault that is planted once the stack has settled has
        /// been planted.
        planted: bool,
    }

    impl Planted {
        /// Plant the fault. The oracle's view of the cluster has been taken,
        /// so what is replaced here is replaced for the engines only.
        fn new(mut late: Late, plant: Plant) -> Self {
            if matches!(plant, Plant::Unrecorded) {
                // The store is paced like the one it replaces, so the run is
                // the one it would be without the fault.
                let node = &mut late.cluster.nodes[late.joiner];
                let unread = Secrets::dealt(node.secrets.share(Epoch::zero()));
                node.secrets = match node.secrets.pacing() {
                    Some(pacing) => unread.paced(pacing),
                    None => unread,
                };
            }
            Self {
                late,
                plant,
                planted: false,
            }
        }
    }

    impl Stack for Planted {
        async fn start(&mut self, index: usize) -> Handle<()> {
            let handle = self.late.start(index).await;
            let cluster = &self.late.cluster;
            match self.plant {
                Plant::Sever(victim) if victim == index => {
                    // Registering a channel again closes the receiver the
                    // engine holds.
                    let participant = &cluster.session.participants[index];
                    drop(reshare_stack::register(&cluster.oracle, participant).await);
                }
                Plant::EnginePanic(victim) if victim == index => {
                    let context = cluster.context.child("planted");
                    drop(EngineContext::new(context, index).spawn(|_| async { panic!("planted") }));
                }
                _ => {}
            }
            handle
        }

        fn crashing(&mut self, index: usize) {
            self.late.crashing(index);
        }

        async fn settled(&mut self, absent: &[bool]) {
            assert!(
                !matches!(self.plant, Plant::HarnessPanic),
                "planted in the harness"
            );
            self.late.settled(absent).await;
            if std::mem::replace(&mut self.planted, true) {
                return;
            }
            let joined = &self.late.joined;
            let synced = joined.steps().iter().find_map(|step| match step {
                Step::Synced(height) => Some(*height),
                _ => None,
            });
            let started = |synced, syncs| {
                joined.stepped(Step::Started(Startup {
                    resumed: None,
                    synced,
                    syncs,
                }));
            };
            match self.plant {
                Plant::Again => started(synced, true),
                Plant::Forgotten => started(None, false),
                Plant::Fork => joined.committed(Height::new(1), Sha256::hash(&[b"planted"])),
                Plant::Redescribed => {
                    let (epoch, info): (Epoch, Info) = joined
                        .deliveries()
                        .pop()
                        .expect("the joiner was delivered a boundary");
                    let outcome = match info.outcome {
                        EpochOutcome::Success => EpochOutcome::Failure,
                        EpochOutcome::Failure => EpochOutcome::Success,
                    };
                    joined.delivered(epoch, Info { outcome, ..info });
                }
                Plant::Block(blocker, blocked) => {
                    let cluster = &self.late.cluster;
                    let participants = &cluster.session.participants;
                    let mut control = cluster.oracle.control(participants[blocker].clone());
                    block!(control, participants[blocked].clone(), "planted block");
                }
                _ => {}
            }
        }

        async fn joined(&mut self) {
            self.late.joined().await;
        }
    }

    /// An input without a crash on which the joiner, engine 0, a member of
    /// the first committee, syncs from a floor above the first height and
    /// before the midpoint of the first epoch, plays the first ceremony, and
    /// the stack settles once.
    fn settling_once() -> DkgStateSyncFuzzInput {
        static INPUT: OnceLock<DkgStateSyncFuzzInput> = OnceLock::new();
        INPUT
            .get_or_init(|| {
                joining(MEMBER, 3..=8)
                    .find(|input| {
                        let report = synced(input.clone());
                        report.sync.floor > Some(Height::new(1))
                            && floor(&report) == (Epoch::zero(), Place::Early)
                    })
                    .expect("no join height of the range has such a floor")
            })
            .clone()
    }

    /// Run the input of [`settling_once`] with `plant` planted.
    fn planted(plant: Plant) -> StateSyncReport {
        execute(settling_once(), false, |late| Planted::new(late, plant)).0
    }

    /// An input on which the joiner, engine 0, is restarted once, after its
    /// sync completed, and does not sync again.
    fn restarted_after_its_sync() -> DkgStateSyncFuzzInput {
        static INPUT: OnceLock<DkgStateSyncFuzzInput> = OnceLock::new();
        INPUT
            .get_or_init(|| {
                [(15, 2), (10, 3), (15, 3), (10, 4), (15, 4)]
                    .into_iter()
                    .map(|(steps, doublings)| {
                        input(1, STAY, MEMBER, 5, after(steps, doublings), 0, 1)
                    })
                    .find(|input| {
                        let sync = synced(input.clone()).sync;
                        (sync.syncs, sync.completions, sync.later) == (1, 1, 1)
                    })
                    .expect("no restart of the range lands after the sync")
            })
            .clone()
    }

    /// Run the input of [`restarted_after_its_sync`] with the joiner's
    /// caller lapsing as `lapse` says.
    fn lapsed(lapse: Lapse) -> StateSyncReport {
        execute(restarted_after_its_sync(), false, |mut late| {
            late.entry = Entry::Lapsed(lapse);
            late
        })
        .0
    }

    impl Retaining for Late {
        /// The epochs the joiner's engine has registered a scheme for.
        type Retained = Vec<Epoch>;

        async fn retained(&mut self, _: usize) -> Vec<Epoch> {
            let registered = self.joined.registrations();
            registered.into_iter().map(|(epoch, _)| epoch).collect()
        }
    }

    /// The cluster with a joiner whose first start leaves its sync without a
    /// completion (see [`Lapse::Stall`]).
    fn stalling(mut late: Late) -> Late {
        late.entry = Entry::Lapsed(Lapse::Stall);
        late
    }

    /// An input on which the joiner, engine 0, a member of the first
    /// committee, enters the first epoch before its midpoint, plays its
    /// ceremony, enters the second epoch at the end of it, and is then
    /// restarted with no completion of its sync on record, so that it syncs
    /// again, from a floor in the second epoch.
    ///
    /// How long an epoch takes depends on the links, and how far the joiner
    /// gets before its crash on the writes its pacing holds, so the restart
    /// is looked for among delays of 1.6 to 9.6 seconds under four tapes.
    fn synced_again_into_a_played_epoch() -> DkgStateSyncFuzzInput {
        static INPUT: OnceLock<DkgStateSyncFuzzInput> = OnceLock::new();
        INPUT
            .get_or_init(|| {
                let delays = [(10, 4), (15, 4), (10, 5), (15, 5), (10, 6), (15, 6)];
                let inputs = delays.into_iter().flat_map(|(steps, doublings)| {
                    (1..=4u16).map(move |seed| {
                        input(2, STAY, MEMBER, 5, after(steps, doublings), 0, seed)
                    })
                });
                fixtures::first(inputs, 4, |input| {
                    let retained = Arc::new(Mutex::new(Vec::new()));
                    let mut joined = None;
                    let (report, _) = execute(input.clone(), false, |late| {
                        joined = Some(late.joined.clone());
                        Watched::new(stalling(late), Arc::clone(&retained))
                    });
                    println!("{report}");
                    let entered: Vec<_> = joined
                        .expect("the cluster was wrapped")
                        .steps()
                        .into_iter()
                        .filter_map(|step| match step {
                            Step::Entered(material) => Some(material.info.epoch),
                            _ => None,
                        })
                        .collect();

                    // What the joiner had registered when it was restarted.
                    let second = Epoch::new(1);
                    let [registered] = &retained.lock()[..] else {
                        return None;
                    };
                    (entered == [Epoch::zero(), second] && registered.contains(&second))
                        .then_some(input)
                })
            })
            .clone()
    }

    /// Run the input of [`synced_again_into_a_played_epoch`], with the
    /// joiner's secret store unread by the oracle if `unrecorded`.
    fn synced_again(unrecorded: bool) -> StateSyncReport {
        let input = synced_again_into_a_played_epoch();
        if unrecorded {
            let planted = |late| Planted::new(stalling(late), Plant::Unrecorded);
            execute(input, false, planted).0
        } else {
            execute(input, false, stalling).0
        }
    }

    /// The joiner's probe loses its channel while it discovers, stops, and
    /// the engine that cannot enter stops with it.
    #[test]
    #[should_panic(expected = "I8 violated: correct engines [0] stopped before the run ended")]
    fn joiner_that_stops_on_its_own_is_rejected() {
        planted(Plant::Sever(0));
    }

    /// An engine that started at genesis is watched like the joiner.
    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped before the run ended")]
    fn engine_that_stops_on_its_own_is_rejected() {
        planted(Plant::Sever(2));
    }

    /// No identity is compromised here, so a panic of any engine is a
    /// violation, whatever it says.
    #[test]
    #[should_panic(expected = "I8 violated: correct engine 0 panicked")]
    fn joiner_panic_is_rejected() {
        planted(Plant::EnginePanic(0));
    }

    #[test]
    #[should_panic(expected = "I8 violated: the run's root task panicked")]
    fn harness_panic_is_rejected() {
        planted(Plant::HarnessPanic);
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 0 chose state sync after its sync completed at height"
    )]
    fn second_sync_is_rejected() {
        planted(Plant::Again);
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 0 lost the record of its state sync, which \
                               completed at height"
    )]
    fn start_that_finds_no_record_of_the_sync_is_rejected() {
        planted(Plant::Forgotten);
    }

    /// The fault is in the caller, not in what is reported of it: a
    /// completed sync is left off the ledger, and the restarted joiner
    /// syncs a second time.
    #[test]
    #[should_panic(
        expected = "I15 violated: engine 0 lost the record of its state sync, which \
                               completed at height"
    )]
    fn caller_that_forgets_its_sync_is_rejected() {
        lapsed(Lapse::Forget);
    }

    /// The caller reports a floor over another block than the one it
    /// started marshal from.
    #[test]
    #[should_panic(expected = "I16 violated: engine 0 started from a floor of round")]
    fn floor_nobody_finalized_is_rejected() {
        lapsed(Lapse::Refloor);
    }

    /// The caller reports another description than the one it paired with
    /// its floor.
    #[test]
    #[should_panic(
        expected = "I16 violated: engine 0 paired its floor with a description of epoch 0 \
                    other than the one the nodes that started at genesis finalized"
    )]
    fn description_nobody_finalized_is_rejected() {
        lapsed(Lapse::Redescribe);
    }

    #[test]
    #[should_panic(expected = "I17 violated: engine 0 committed block")]
    fn block_the_others_did_not_commit_is_rejected() {
        planted(Plant::Fork);
    }

    #[test]
    #[should_panic(expected = "I17 violated: engine 0 committed a description of epoch")]
    fn description_the_others_did_not_commit_is_rejected() {
        planted(Plant::Redescribed);
    }

    /// The joiner entered the first epoch through state sync, before the
    /// midpoint, and played its ceremony. I2 excuses it nothing there: it
    /// must hold a share of the output.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 0 completed the successful reshare into epoch 1 as a \
                    player of its output and holds no share of it"
    )]
    fn joiner_that_played_a_ceremony_without_a_share_is_rejected() {
        planted(Plant::Unrecorded);
    }

    /// The joiner played the first ceremony after it entered through state
    /// sync, entered the second epoch on its own, and synced again from a
    /// floor in that epoch. The second sync excuses it nothing: it is a
    /// player of every output of the run and is counted as one.
    #[test]
    fn joiner_that_syncs_again_into_an_epoch_it_played_for_is_a_player_of_it() {
        let report = synced_again(false);
        assert_synced(&report);
        let (sync, counts) = (report.sync, report.counts);
        assert_eq!(
            (sync.starts, sync.syncs, sync.entries),
            (2, 2, 2),
            "{report}"
        );
        assert_eq!((sync.resumptions, sync.boundaries), (1, 1), "{report}");
        assert_eq!(counts.failures, 0, "{report}");
        assert_eq!(counts.players, 4 * counts.epochs, "{report}");
    }

    /// The same run with no share of the joiner on record: the second sync
    /// does not excuse it the share of the output it played for.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 0 completed the successful reshare into epoch 1 as a \
                    player of its output and holds no share of it"
    )]
    fn joiner_that_syncs_again_into_an_epoch_it_played_for_must_hold_its_share() {
        synced_again(true);
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_is_rejected() {
        planted(Plant::Block(0, 3));
    }
}

//! The bootstrap restart driver: four correct identities, no byzantine
//! behaviour.
//!
//! Every identity runs one real bootstrap engine and the only faults are
//! environmental: the engines are crashed and restarted on a schedule drawn
//! from the tape, and the links among them delay, lose, and for a while cut
//! off what they carry, as the input directs. A restart keeps the identity's
//! storage partitions and its secret store, so the engine it brings back
//! replays its journals, resumes its dealer and its player, and re-enters the
//! ceremony wherever the crash left it. An engine restarted after it applied
//! the chain's final block reports the ceremony again from that block.
//!
//! The secret stores and the engines' storage are paced (see
//! [`pacing`](super::pacing)): some of the writes an engine makes shortly
//! before one of its crashes are held, so the crash can fall between two
//! writes the engine makes one after the other.
//!
//! The run ends when the schedule has been played out, the latest instance
//! of every engine has reported its completion, and every engine a restart
//! brought back has applied a block since that restart or the environment's
//! bound on that wait has passed; when an engine stops on its own; or when
//! the bounded timeout expires. An engine restarted after the chain's final
//! block reports as it sets itself up and has no further block to apply, so
//! the run goes on for that bound after its restart (see [`environment`]).
//! The invariants are checked over whatever was reached. Because every
//! identity is correct, they are checked over all four, no panic is
//! tolerated, and every report an engine makes, before and after a restart,
//! must be the same.
//!
//! The ceremony is over for the driver once every engine has reported, so an
//! event of the schedule that is still to come then runs at once instead of
//! at its time (see [`environment`]). A crash after the ceremony therefore
//! costs no idle time, and an identity that is down or cut off while the
//! others finish is brought back as soon as they have.

use super::{
    BOOTSTRAP_RUN_TIMEOUT, DkgBootstrapRestartsFuzzInput, Outcome, PublicKey,
    environment::{self, Landing, Program, Stack, position, processed_height},
    identities,
    invariants::{self, Ceremony, Counts, Ending, Instance, Observed, Reports},
    pacing::{PacedCounts, Trace},
    public_keys,
    runner::{self, Report},
    stack,
    store::Secrets,
};
use crate::stateful::runner::network_with;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{bls12381::primitives::sharing::Mode, ed25519};
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{NZUsize, channel::mpsc, ordered::Set, sync::Mutex};
use std::{fmt, sync::Arc, time::Duration};

/// Label the driver reports under.
const TARGET: &str = "glue-dkg-bootstrap-restarts";

/// The epoch after the one epoch of the bootstrap chain. An engine that has
/// entered it has applied the chain's final block.
const LAST: Epoch = Epoch::new(1);

/// How much of its restart schedule a run performed, and where each crash
/// found its engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestartCounts {
    /// Engines the schedule crashed.
    pub crashes: usize,
    /// Crashed engines the schedule brought back before the run ended.
    pub restarts: usize,
    /// Crashes that found the engine in the dealing window.
    pub dealing: usize,
    /// Crashes that found the engine in the inclusion window.
    pub inclusion: usize,
    /// Crashes that found the engine past the chain's final block.
    pub finished: usize,
    /// Restarts whose engine started holding its share of the output.
    pub with_share: usize,
    /// Reports an engine repeated after a restart, each compared with its
    /// first under I1.
    pub repeated_reports: usize,
    /// How the writes the pacing held ended: how many crashes dropped one,
    /// and what each dropped write left behind.
    pub paced: PacedCounts,
}

/// What one bootstrap restart run observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapRestartsReport {
    /// Why the run stopped.
    pub outcome: Outcome,
    /// How much each check compared.
    pub counts: Counts,
    /// What the restart schedule did.
    pub restarts: RestartCounts,
    /// Engines whose latest instance a restart started, each of which the
    /// end of the run followed.
    pub followed: usize,
    /// Of those, the engines the end of the run waited for until the bound
    /// on that wait had passed, with no block applied since their restart.
    pub expired: usize,
    /// The simulated time from the last restart of the run to its end.
    pub after: Duration,
    /// The blocks the engine of that restart applied in that time.
    pub after_blocks: u64,
    /// The simulated time the run took.
    pub elapsed: Duration,
}

impl fmt::Display for BootstrapRestartsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} correct_nodes={} completed={} successes={} agreements={} \
             shares={} reconstructions={} blocks={} crashes={} restarts={} dealing={} \
             inclusion={} finished={} with_share={} repeated_reports={} {} followed={} \
             expired={} after_ms={} after_blocks={} elapsed_ms={}",
            self.outcome,
            self.counts.correct_nodes,
            self.counts.completed,
            self.counts.successes,
            self.counts.agreements,
            self.counts.shares,
            self.counts.reconstructions,
            self.counts.blocks,
            self.restarts.crashes,
            self.restarts.restarts,
            self.restarts.dealing,
            self.restarts.inclusion,
            self.restarts.finished,
            self.restarts.with_share,
            self.restarts.repeated_reports,
            self.restarts.paced,
            self.followed,
            self.expired,
            self.after.as_millis(),
            self.after_blocks,
            self.elapsed.as_millis(),
        )
    }
}

impl Report for BootstrapRestartsReport {
    fn measured(&self) -> bool {
        self.counts.completed > 0
    }
}

/// libFuzzer entry point.
pub fn fuzz_dkg_bootstrap_restarts(input: DkgBootstrapRestartsFuzzInput) {
    runner::fuzz(input.raw_bytes.clone(), input, run_dkg_bootstrap_restarts);
}

/// Run one bootstrap ceremony under one restart schedule and one set of link
/// conditions and return what it measured.
///
/// A run is fully determined by its input.
pub fn run_dkg_bootstrap_restarts(input: DkgBootstrapRestartsFuzzInput) -> BootstrapRestartsReport {
    execute(input, |cluster| cluster).0
}

/// Run `input` over the stack `wrap` makes of the cluster of real engines.
/// Returns what the run measured and what its pacing did.
///
/// libFuzzer runs the cluster itself. A test wraps it to plant a fault at the
/// boundary the oracle observes, or to observe what a restart finds.
fn execute<S: Stack>(
    input: DkgBootstrapRestartsFuzzInput,
    wrap: impl FnOnce(Cluster) -> S,
) -> (BootstrapRestartsReport, Trace) {
    let entropy = input.raw_bytes.clone();
    let (observed, panics) = runner::execute(entropy.clone(), |context| {
        run(context, input, entropy, wrap)
    });

    // Measurement point, outside the runtime so a violation is never caught.
    // No identity is compromised, so no panic is tolerated.
    invariants::check_panics(&panics, &[]);
    let crashes = invariants::check_instances_running(&observed.instances);
    let repeated_reports =
        invariants::check_reports_agree(observed.ceremony.epoch, &observed.reports);
    let counts =
        invariants::check_bootstrap(&observed.ceremony, &observed.committee, &observed.blocked);
    let report = BootstrapRestartsReport {
        outcome: observed.outcome,
        counts,
        restarts: RestartCounts {
            crashes,
            repeated_reports,
            paced: observed.paced.counts(),
            ..observed.restarts
        },
        followed: observed.followed,
        expired: observed.expired,
        after: observed.after,
        after_blocks: observed.after_blocks,
        elapsed: observed.elapsed,
    };
    (report, observed.paced)
}

/// What a run observed, to be checked once the runtime has stopped.
struct Observations {
    outcome: Outcome,
    ceremony: Ceremony,
    /// The identities the ceremony is among, in identity order.
    committee: Arc<[PublicKey]>,
    /// What each engine's instances reported.
    reports: Vec<Reports>,
    /// Every engine instance the run started.
    instances: Vec<Instance>,
    blocked: Vec<(PublicKey, PublicKey)>,
    /// What the driver saw of the schedule. The counts the checks produce
    /// and the pacing's are filled in at the measurement point.
    restarts: RestartCounts,
    /// What the pacing did.
    paced: Trace,
    /// What the end of the run saw of the engines a restart brought back
    /// (see [`BootstrapRestartsReport`]).
    followed: usize,
    expired: usize,
    after: Duration,
    after_blocks: u64,
    elapsed: Duration,
}

/// One identity's engine across its restarts.
#[derive(Default)]
struct Node {
    /// Instances of the engine started so far.
    starts: usize,
    /// The reports of the engine's instances, each with the number of the
    /// instance that made it, in the order they were made.
    reports: Arc<Mutex<Vec<(usize, Ending)>>>,
}

/// The cluster of real bootstrap engines: what each identity runs with, kept
/// across its restarts.
struct Cluster {
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    signers: Vec<ed25519::PrivateKey>,
    participants: Arc<[PublicKey]>,
    committee: Set<PublicKey>,
    sharing_mode: Mode,
    /// One secret store per identity, held here so that it survives the
    /// identity's restarts and the oracle can read it.
    secrets: Vec<Secrets>,
    nodes: Vec<Node>,
    /// Signalled by every report an engine makes.
    reported: mpsc::UnboundedSender<()>,
    progress: mpsc::UnboundedReceiver<()>,
    /// What the schedule did, shared so the driver can read it after the run.
    restarts: Arc<Mutex<RestartCounts>>,
}

impl Cluster {
    fn new(
        context: deterministic::Context,
        oracle: Oracle<PublicKey, deterministic::Context>,
        signers: Vec<ed25519::PrivateKey>,
        sharing_mode: Mode,
        program: &Program,
    ) -> Self {
        let participants: Arc<[PublicKey]> = public_keys(&signers);
        let committee = Set::from_iter_dedup(participants.iter().cloned());
        let (reported, progress) = mpsc::unbounded_channel();
        Self {
            context,
            oracle,
            secrets: (0..signers.len())
                .map(|index| Secrets::default().paced(program.pacing(index)))
                .collect(),
            nodes: signers.iter().map(|_| Node::default()).collect(),
            signers,
            participants,
            committee,
            sharing_mode,
            reported,
            progress,
            restarts: Arc::default(),
        }
    }

    /// Whether the latest instance of every engine has reported, leaving
    /// out the identities marked in `absent`.
    fn reported_by_all(&self, absent: &[bool]) -> bool {
        self.nodes.iter().zip(absent).all(|(node, absent)| {
            *absent
                || node
                    .reports
                    .lock()
                    .last()
                    .is_some_and(|(instance, _)| instance + 1 == node.starts)
        })
    }
}

impl Stack for Cluster {
    async fn start(&mut self, index: usize) -> Handle<()> {
        let node = &mut self.nodes[index];
        let instance = node.starts;
        node.starts += 1;
        if instance > 0 {
            let mut restarts = self.restarts.lock();
            restarts.restarts += 1;
            if self.secrets[index].share(Epoch::zero()).is_some() {
                restarts.with_share += 1;
            }
        }

        // Registering a channel again replaces the registration the crashed
        // instance held.
        let channels = stack::register(&self.oracle, &self.participants[index]).await;
        let (node_context, context) = environment::contexts(&self.context, index);
        let (handle, completion) = stack::spawn(
            context,
            &self.oracle,
            stack::Config {
                signer: self.signers[index].clone(),
                participants: self.committee.clone(),
                partition: format!("engine-{index}"),
                secrets: self.secrets[index].clone(),
                sharing_mode: self.sharing_mode,
            },
            channels.votes,
            channels.certificates,
            channels.resolver,
            channels.backfill,
            channels.broadcast,
            channels.dkg,
        );

        // An instance crashed before it reports leaves no record.
        let reports = node.reports.clone();
        let reported = self.reported.clone();
        drop(node_context.child("completion").spawn(move |_| async move {
            let Ok(completion) = completion.await else {
                return;
            };
            reports.lock().push((instance, stack::ending(completion)));
            let _ = reported.send(());
        }));
        handle
    }

    fn crashing(&mut self, index: usize) {
        let processed = processed_height(&self.context, index).unwrap_or_default();
        let mut restarts = self.restarts.lock();
        // The height alone places no engine at a boundary.
        match position(processed, LAST).1 {
            Landing::Dealing => restarts.dealing += 1,
            Landing::Inclusion | Landing::Boundary => restarts.inclusion += 1,
            Landing::Finished => restarts.finished += 1,
        }
    }

    async fn settled(&mut self, absent: &[bool]) {
        while !self.reported_by_all(absent) {
            if self.progress.recv().await.is_none() {
                return std::future::pending().await;
            }
        }
    }

    fn follows(&self) -> bool {
        true
    }
}

async fn run<S: Stack>(
    context: deterministic::Context,
    input: DkgBootstrapRestartsFuzzInput,
    entropy: Vec<u8>,
    wrap: impl FnOnce(Cluster) -> S,
) -> Observations {
    let signers = identities();
    let link = input.environment.links.link();
    let program = Program::new(&input.environment, entropy, signers.len());
    let cluster = Cluster::new(
        environment::cluster(&context),
        network_with(
            &context,
            &public_keys::<Vec<_>>(&signers),
            link.clone(),
            NZUsize!(1),
        )
        .await,
        signers,
        input.sharing_mode,
        &program,
    );
    let oracle = cluster.oracle.clone();
    let participants = cluster.participants.clone();
    let secrets = cluster.secrets.clone();
    let reports: Vec<_> = cluster
        .nodes
        .iter()
        .map(|node| node.reports.clone())
        .collect();
    let restarts = cluster.restarts.clone();

    let mut stack = wrap(cluster);
    let played = environment::play(
        &context,
        &oracle,
        &participants,
        link,
        program,
        &mut stack,
        BOOTSTRAP_RUN_TIMEOUT,
    )
    .await;

    // Every identity is correct, so every engine is in the records.
    let blocked = runner::blocked(&oracle).await;
    let reports: Vec<Reports> = reports
        .iter()
        .enumerate()
        .map(|(engine, reports)| Reports {
            engine,
            endings: reports
                .lock()
                .iter()
                .map(|(_, ending)| ending.clone())
                .collect(),
        })
        .collect();
    let last = played.last_restarted().copied();
    let ceremony = Ceremony {
        epoch: Epoch::zero(),
        nodes: reports
            .iter()
            .map(|reports| Observed {
                engine: reports.engine,
                identity: participants[reports.engine].clone(),
                ending: reports.endings.first().cloned(),
                share: secrets[reports.engine].share(Epoch::zero()),
            })
            .collect(),
    };
    Observations {
        outcome: played.outcome,
        ceremony,
        committee: participants,
        reports,
        followed: played.followed.len(),
        expired: played.expired(),
        after: last.map_or(Duration::ZERO, |last| last.lasted),
        after_blocks: last.map_or(0, |last| last.blocks),
        instances: played.instances,
        blocked,
        restarts: *restarts.lock(),
        paced: played.paced,
        elapsed: played.elapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        Cut, CutScope, EnvironmentControls, LinkControls, MockGroup,
        context::EngineContext,
        environment::{CUT_STEP, Event, FOLLOW},
        fixtures::{
            self, CLEAN, LOSSY, Retaining, Sample, Sampled, Watched, cut, decode, journal, sample,
            tape,
        },
        pacing::{Change, Operation, Partition, Secret, Stage},
    };
    use commonware_cryptography::bls12381::dkg::feldman_desmedt::deal;
    use commonware_p2p::{Blocker as _, block};
    use commonware_utils::{N3f1, TestRng};

    fn input(
        restarts: u8,
        links: LinkControls,
        cuts: Vec<Cut>,
        seed: u16,
    ) -> DkgBootstrapRestartsFuzzInput {
        DkgBootstrapRestartsFuzzInput {
            sharing_mode: Mode::NonZeroCounter,
            environment: EnvironmentControls {
                restarts,
                links,
                cuts,
            },
            raw_bytes: tape(seed),
        }
    }

    /// The restart schedule `input` draws from its tape, in milliseconds
    /// from the start of the run.
    fn schedule(input: &DkgBootstrapRestartsFuzzInput) -> Vec<(u128, Event)> {
        fixtures::schedule(&input.environment, &input.raw_bytes, identities().len())
    }

    /// What an identity had retained when a restart of its engine began.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Retained {
        engine: usize,
        /// Whether its secret store held its dealer seed.
        seed: bool,
        /// How many private dealings its secret store held.
        dealings: usize,
        /// Whether its secret store held its share of the output.
        share: bool,
        /// The durable length of the reshare actor's journal.
        journal: u64,
    }

    impl Retaining for Cluster {
        type Retained = Retained;

        async fn retained(&mut self, index: usize) -> Retained {
            let secrets = &self.secrets[index];
            let (seed, dealings, share) = (
                secrets.seeded(Epoch::zero()),
                secrets.dealings(Epoch::zero()),
                secrets.share(Epoch::zero()).is_some(),
            );
            Retained {
                engine: index,
                seed,
                dealings,
                share,
                journal: journal(&self.context, index).await,
            }
        }
    }

    /// One run of an input over the watched cluster.
    struct Run {
        report: BootstrapRestartsReport,
        /// What the pacing did.
        trace: Trace,
        /// What each restart found, in the order of the restarts.
        retained: Vec<Retained>,
    }

    /// Run `input` over the watched cluster, and assert that no two
    /// identities were impaired at once.
    fn watched(input: DkgBootstrapRestartsFuzzInput) -> Run {
        let retained = Arc::new(Mutex::new(Vec::new()));
        let (report, trace) = execute(input, |cluster| {
            Watched::new(cluster, Arc::clone(&retained))
        });
        println!("{report}");
        assert_eq!(trace.overlaps(), 0, "{:?}", trace.impairments());
        let retained = retained.lock().clone();
        Run {
            report,
            trace,
            retained,
        }
    }

    /// Run one fixed input and assert that its checks were not vacuous: the
    /// ceremony succeeded at all four engines and every check compared them.
    fn succeeded(input: DkgBootstrapRestartsFuzzInput) -> Run {
        let run = watched(input);
        let report = run.report;
        assert_eq!(report.outcome, Outcome::Completed, "{report}");
        assert_eq!(report.counts.correct_nodes, 4, "{report}");
        assert_eq!(report.counts.completed, 4, "{report}");
        assert_eq!(report.counts.successes, 1, "{report}");
        assert_eq!(report.counts.agreements, 3, "{report}");
        assert_eq!(report.counts.shares, 4, "{report}");

        // Four holders and three required: four subsets reconstruct.
        assert_eq!(report.counts.reconstructions, 4, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
        run
    }

    /// Lists, for each seed of a range, the schedule of the input over
    /// clean links, what its run came to, the held writes each crash
    /// dropped, and what each restart found. The fixed inputs of the tests
    /// here were chosen from this listing. `SURVEY` names the number of
    /// restarts and the seeds, as in `1:0..600`.
    #[test]
    #[ignore = "a listing to choose fixed inputs from"]
    fn survey() {
        let range = std::env::var("SURVEY").unwrap_or_else(|_| "1:0..600".into());
        let (restarts, seeds) = range.split_once(':').expect("restarts:from..to");
        let (from, to) = seeds.split_once("..").expect("restarts:from..to");
        let restarts: u8 = restarts.parse().expect("restarts");
        let (from, to): (u16, u16) = (from.parse().expect("from"), to.parse().expect("to"));
        for seed in from..to {
            let input = input(restarts, CLEAN, Vec::new(), seed);
            let schedule = schedule(&input);
            let retained = Arc::new(Mutex::new(Vec::new()));
            let (report, trace) = execute(input, |cluster| {
                Watched::new(cluster, Arc::clone(&retained))
            });
            let dropped: Vec<_> = (0..4)
                .map(|engine| (engine, trace.dropped(engine)))
                .filter(|(_, dropped)| !dropped.is_empty())
                .collect();
            println!(
                "SURVEY seed={seed} schedule={schedule:?} dropped={dropped:?} retained={:?} \
                 overlaps={} {report}",
                retained.lock(),
                trace.overlaps()
            );
        }
    }

    /// The write that stores the private half of a dealing.
    const PRIVATE_HALF: Operation = Operation::Secret(Secret::Dealing);

    /// The write that stores the engine's share of the output.
    const SHARE: Operation = Operation::Secret(Secret::Share);

    /// What the one restart of `run` found.
    fn found(run: &Run) -> Retained {
        let [retained] = run.retained[..] else {
            panic!("the run has one restart: {:?}", run.retained);
        };
        retained
    }

    /// The engine is crashed while dealings and acks are exchanged, between
    /// the two writes that record the first dealing it received. The write
    /// of the private half was held after it was applied, so the secret
    /// store holds the dealing although the engine never saw it stored. The
    /// journal entry was written to its blob and its sync was held before it
    /// was applied, so the crash discarded the entry with the blob although
    /// the write of it had resolved. The engine that comes back finds a
    /// private half that no journal entry names, is dealt the dealing again,
    /// and the ceremony's result is checked at all four.
    ///
    /// The seed is the first of the seeds 0 to 4499 whose crash, in the
    /// listing of [`survey`] for one restart, dropped these two writes and
    /// no other.
    #[test]
    fn crash_in_the_dealing_window_is_survived() {
        let input = input(1, CLEAN, Vec::new(), 1592);
        assert_eq!(
            schedule(&input),
            vec![(6_400, Event::Crash(3)), (12_800, Event::Restart(3))]
        );
        let run = succeeded(input);
        assert_eq!(
            run.trace.dropped(3),
            vec![
                (PRIVATE_HALF, Stage::After),
                (
                    Operation::Blob(Partition::Journal, Change::Sync),
                    Stage::Before
                ),
            ]
        );

        // The two writes were in flight together, until the crash.
        let [private, journal] = run.trace.holds() else {
            panic!("two writes were held: {:?}", run.trace.holds());
        };
        assert!(private.from <= journal.from && journal.from < private.until.unwrap());
        assert_eq!(private.until, journal.until);

        // What the crash left: the private half, and nothing in the journal.
        assert_eq!(
            found(&run),
            Retained {
                engine: 3,
                seed: true,
                dealings: 1,
                share: false,
                journal: 0,
            }
        );
        let restarts = run.report.restarts;
        assert_eq!(
            (restarts.crashes, restarts.restarts, restarts.dealing),
            (1, 1, 1)
        );
    }

    /// The other split of a dealing: its journal entry is durable and the
    /// write of its private half was held before it was applied, so the
    /// crash leaves a journaled dealing that the secret store does not hold.
    /// The engine that comes back drops that dealing when it replays its
    /// journal, and still ends the ceremony with a valid share.
    ///
    /// The seed is the first of the same listing whose crash dropped that
    /// write and no other while the secret store held no dealing yet.
    #[test]
    fn crash_that_leaves_a_journaled_dealing_without_its_private_half_is_survived() {
        let input = input(1, CLEAN, Vec::new(), 1467);
        assert_eq!(
            schedule(&input),
            vec![(150, Event::Crash(3)), (7_350, Event::Restart(3))]
        );
        let run = succeeded(input);
        assert_eq!(run.trace.dropped(3), vec![(PRIVATE_HALF, Stage::Before)]);
        assert_eq!(run.trace.holds().len(), 1);

        // What the crash left: a journal that holds an entry, and no
        // private half.
        let found = found(&run);
        assert_eq!((found.engine, found.dealings), (3, 0), "{found:?}");
        assert!(found.journal > 0, "{found:?}");
        let restarts = run.report.restarts;
        assert_eq!(
            (restarts.crashes, restarts.restarts, restarts.dealing),
            (1, 1, 1)
        );
    }

    /// The engine is crashed after the midpoint, while dealer logs are being
    /// included, and completes the ceremony after its restart. This crash
    /// draws no pacing.
    #[test]
    fn crash_in_the_inclusion_window_is_survived() {
        let input = input(1, CLEAN, Vec::new(), 27);
        assert_eq!(
            schedule(&input),
            vec![(1_400, Event::Crash(3)), (2_600, Event::Restart(3))]
        );
        let report = succeeded(input).report;
        assert_eq!(
            report.restarts,
            RestartCounts {
                crashes: 1,
                restarts: 1,
                inclusion: 1,
                ..RestartCounts::default()
            }
        );
    }

    /// The engine has derived its share from the final block and the write
    /// that stores it is held before it is applied. The crash drops it, so
    /// the engine that comes back holds no share, applies the final block
    /// again, and derives and stores the share anew.
    ///
    /// The seed is the first of the listing of [`survey`] for one restart
    /// whose crash dropped that write and no other.
    #[test]
    fn crash_before_the_share_is_stored_is_survived() {
        let input = input(1, CLEAN, Vec::new(), 330);
        assert_eq!(
            schedule(&input),
            vec![(1_600, Event::Crash(1)), (2_600, Event::Restart(1))]
        );
        let run = succeeded(input);
        assert_eq!(run.trace.dropped(1), vec![(SHARE, Stage::Before)]);
        assert_eq!(run.trace.holds().len(), 1);
        let found = found(&run);
        assert_eq!((found.engine, found.share), (1, false), "{found:?}");
        assert_eq!(
            run.report.restarts,
            RestartCounts {
                crashes: 1,
                restarts: 1,
                inclusion: 1,
                paced: run.report.restarts.paced,
                ..RestartCounts::default()
            }
        );
    }

    /// The write that stores the share is held after it is applied, and the
    /// crash drops it: the share is in the secret store although the engine
    /// never saw it stored and never acknowledged the final block. The
    /// engine that comes back finds its share and reports the ceremony from
    /// the final block its marshal stored. It is the engine's only report.
    ///
    /// The seed is the first of the same listing whose crash dropped that
    /// write, after it was applied, and no other.
    #[test]
    fn crash_after_the_share_is_stored_is_survived() {
        let input = input(1, CLEAN, Vec::new(), 390);
        assert_eq!(
            schedule(&input),
            vec![(1_500, Event::Crash(3)), (3_100, Event::Restart(3))]
        );
        let run = succeeded(input);
        assert_eq!(run.trace.dropped(3), vec![(SHARE, Stage::After)]);
        assert_eq!(run.trace.holds().len(), 1);
        let found = found(&run);
        assert_eq!((found.engine, found.share), (3, true), "{found:?}");
        assert_eq!(
            run.report.restarts,
            RestartCounts {
                crashes: 1,
                restarts: 1,
                inclusion: 1,
                with_share: 1,
                paced: run.report.restarts.paced,
                ..RestartCounts::default()
            }
        );
    }

    /// The engine stays down while the other three finish the ceremony. Its
    /// restart is brought forward, and it learns the chain from them.
    #[test]
    fn engine_that_returns_after_the_ceremony_catches_up() {
        for (seed, crash, restart, landed) in [
            (7, 400, 32_400, Landing::Dealing),
            (29, 1_400, 33_400, Landing::Inclusion),
        ] {
            let input = input(1, CLEAN, Vec::new(), seed);
            let victim = match &schedule(&input)[..] {
                [
                    (crashed, Event::Crash(victim)),
                    (restarted, Event::Restart(_)),
                ] if (*crashed, *restarted) == (crash, restart) => *victim,
                schedule => panic!("unexpected schedule: {schedule:?}"),
            };
            assert!(victim < 4);
            let report = succeeded(input).report;
            assert_eq!(
                report.restarts,
                RestartCounts {
                    crashes: 1,
                    restarts: 1,
                    dealing: usize::from(landed == Landing::Dealing),
                    inclusion: usize::from(landed == Landing::Inclusion),
                    paced: report.restarts.paced,
                    ..RestartCounts::default()
                }
            );
            assert!(report.elapsed < Duration::from_millis(restart as u64));
        }
    }

    /// The engine is crashed after it reported. Its restart finds its share
    /// and the final block, reports the ceremony again from them, and the
    /// two reports are compared.
    #[test]
    fn engine_restarted_after_the_ceremony_reports_it_again() {
        let input = input(1, CLEAN, Vec::new(), 2);
        assert_eq!(
            schedule(&input),
            vec![(1_600, Event::Crash(3)), (6_400, Event::Restart(3))]
        );
        let report = succeeded(input).report;
        assert_eq!(
            report.restarts,
            RestartCounts {
                crashes: 1,
                restarts: 1,
                finished: 1,
                with_share: 1,
                repeated_reports: 1,
                paced: report.restarts.paced,
                ..RestartCounts::default()
            }
        );
    }

    /// The engine crashed after the chain's final block reports again as it
    /// sets itself up, which is all the cluster waits for of it, and the
    /// chain has no further block for it to apply. The run goes on until the
    /// bound on following a restarted engine has passed since its restart,
    /// and the engine is still running when it ends.
    #[test]
    fn engine_restarted_after_the_final_block_is_followed_for_a_bounded_time() {
        let report = fixtures::first(0..200, 4, |seed| {
            let report = watched(input(1, CLEAN, Vec::new(), seed)).report;
            let restarts = report.restarts;
            (report.outcome == Outcome::Completed
                && (restarts.crashes, restarts.restarts, restarts.finished) == (1, 1, 1))
                .then_some(report)
        });
        assert_eq!(report.counts.completed, 4, "{report}");
        assert_eq!(report.restarts.repeated_reports, 1, "{report}");
        assert_eq!(
            (report.followed, report.expired, report.after_blocks),
            (1, 1, 0),
            "{report}"
        );
        assert!(report.after >= FOLLOW, "{report}");
        assert!(
            report.after < FOLLOW + Duration::from_millis(20),
            "{report}"
        );
    }

    /// A full schedule over clean links: every crash is followed by its
    /// restart, and the crashes land in every part of the ceremony.
    #[test]
    fn repeated_restarts_hold_invariants() {
        let mut landed = RestartCounts::default();
        let mut dropped = Vec::new();
        for seed in [0, 1, 4, 14, 20, 21] {
            let run = succeeded(input(4, CLEAN, Vec::new(), seed));
            let report = run.report;
            assert_eq!(report.restarts.crashes, 4, "{report}");
            assert_eq!(report.restarts.restarts, 4, "{report}");
            landed.dealing += report.restarts.dealing;
            landed.inclusion += report.restarts.inclusion;
            landed.finished += report.restarts.finished;
            landed.repeated_reports += report.restarts.repeated_reports;
            landed.paced += report.restarts.paced;
            dropped.extend((0..4).flat_map(|engine| run.trace.dropped(engine)));
        }
        assert!(landed.dealing > 0, "{landed:?}");
        assert!(landed.inclusion > 0, "{landed:?}");
        assert!(landed.finished > 0, "{landed:?}");
        assert!(landed.repeated_reports > 0, "{landed:?}");

        // Some of the crashes fell inside a held write: of the DKG module's
        // own state and of the chain's, before it was applied and after.
        assert!(landed.paced.crashes > 0, "{landed:?}");
        for stage in [Stage::Before, Stage::After] {
            for dkg in [true, false] {
                assert!(
                    dropped
                        .iter()
                        .any(|(operation, at)| operation.dkg() == dkg && *at == stage),
                    "{stage:?} {dkg}: {dropped:?}"
                );
            }
        }
    }

    /// Slow, jittery, lossy links with a cut of every scope, under restarts.
    #[test]
    fn lossy_links_and_cuts_hold_invariants() {
        for (seed, cuts) in [
            (
                11,
                vec![
                    cut(0, 6, 0, CutScope::Both),
                    cut(2, 4, 1, CutScope::Outbound),
                    cut(1, 8, 2, CutScope::Inbound),
                ],
            ),
            (
                12,
                vec![
                    cut(1, 30, 3, CutScope::To(0)),
                    cut(0, 2, 3, CutScope::Inbound),
                ],
            ),
        ] {
            let report = succeeded(input(3, LOSSY, cuts, seed)).report;
            assert_eq!(report.restarts.crashes, 3, "{report}");
        }
    }

    /// One identity hears nothing and is not heard until the other three
    /// have finished, so no dealing reaches it in the dealing window and none
    /// of its own is acknowledged. The ceremony still succeeds, and once the
    /// cut is healed the identity derives a valid share from the chain.
    #[test]
    fn identity_cut_off_through_the_dealing_window_recovers_its_share() {
        let cuts = vec![cut(0, 64, 2, CutScope::Both)];
        let report = succeeded(input(1, CLEAN, cuts, 3)).report;

        // The cut would have lasted 32 seconds. It is healed as soon as the
        // other three have finished.
        assert!(report.elapsed < CUT_STEP * 64, "{report}");
    }

    /// An input on which the ceremony fails (see [`fixtures::failing`]).
    fn failing() -> DkgBootstrapRestartsFuzzInput {
        let (links, cuts, seed) = fixtures::failing();
        let input = input(1, links, cuts, seed);
        assert_eq!(schedule(&input), fixtures::failing_schedule());
        input
    }

    /// All four engines agree that the ceremony failed, the restarted one
    /// included, and none holds a share (I1, I6).
    #[test]
    fn failed_ceremony_is_agreed_and_leaves_no_share() {
        let report = watched(failing()).report;
        assert_eq!(report.outcome, Outcome::Completed);
        assert_eq!(
            report.counts,
            Counts {
                correct_nodes: 4,
                completed: 4,
                agreements: 3,
                ..Counts::default()
            }
        );
        assert_eq!(
            report.restarts,
            RestartCounts {
                crashes: 1,
                restarts: 1,
                dealing: 1,
                ..RestartCounts::default()
            }
        );
    }

    /// An input on which pacing makes the ceremony fail. The first identity
    /// the schedule crashes has three writes held from a tenth of a second
    /// into the run until its crash, more than four seconds later: an entry
    /// of the reshare actor's journal and a write of marshal's, both before
    /// they were applied, and a write of the Simplex journal after it was
    /// applied. Its reshare actor, its marshal, and its voter wait on them,
    /// so it is slow and then down for five seconds in all, and the next
    /// identity is crashed three tenths of a second after it comes back,
    /// before the ceremony is over. The two are never impaired together.
    /// All four engines agree that the ceremony failed, the restarted ones
    /// included, and none holds a share (I1, I6).
    ///
    /// The seed is the first of the seeds 0 to 119 on which, in the listing
    /// of [`survey`] for four restarts, the ceremony fails.
    #[test]
    fn ceremony_that_fails_under_pacing_is_agreed_and_leaves_no_share() {
        let input = input(4, CLEAN, Vec::new(), 5);
        assert_eq!(
            schedule(&input)[..4],
            [
                (4_400, Event::Crash(1)),
                (5_000, Event::Restart(1)),
                (5_300, Event::Crash(3)),
                (30_900, Event::Restart(3)),
            ]
        );
        let run = watched(input);
        let report = run.report;
        assert_eq!(report.outcome, Outcome::Completed);
        assert_eq!(
            report.counts,
            Counts {
                correct_nodes: 4,
                completed: 4,
                agreements: 3,
                ..Counts::default()
            }
        );
        assert_eq!(report.restarts.crashes, 4, "{report}");

        // The first crash dropped the three writes, and the others none.
        let write = |synced| Change::Write { synced };
        assert_eq!(
            run.trace.dropped(1),
            vec![
                (
                    Operation::Blob(Partition::Chain, write(false)),
                    Stage::Before
                ),
                (
                    Operation::Blob(Partition::Journal, write(true)),
                    Stage::Before
                ),
                (
                    Operation::Blob(Partition::Consensus, write(false)),
                    Stage::After
                ),
            ]
        );
        assert_eq!(run.trace.holds().len(), 3);

        // The first identity is impaired from its first held write until
        // its restart, and the second from its crash.
        let impairments = run.trace.impairments();
        assert_eq!((impairments[0].engine, impairments[1].engine), (1, 3));
        assert!(impairments[0].from < Duration::from_millis(200));
        let back = impairments[0].until.expect("the first identity came back");
        assert!(back >= Duration::from_secs(5) && back < impairments[1].from);
    }

    #[test]
    fn roots_of_unity_runs() {
        let mut input = input(2, CLEAN, Vec::new(), 9);
        input.sharing_mode = Mode::RootsOfUnity;
        let report = succeeded(input).report;
        assert_eq!(report.restarts.crashes, 2);
    }

    /// Inputs decoded the way libFuzzer's are, through the entry point it
    /// calls.
    #[test]
    fn decoded_inputs_run_through_the_entry_point() {
        for bytes in [&[][..], &[0x5a], &[0x01, 0x02, 0x03], &[0xff; 24]] {
            let input: DkgBootstrapRestartsFuzzInput = decode(bytes);
            fuzz_dkg_bootstrap_restarts(input.clone());
            let report = watched(input).report;
            assert_eq!(report.counts.correct_nodes, 4);
            assert!(report.restarts.crashes > 0, "{report}");
        }
    }

    /// I10: a replayed input measures the same thing, down to the simulated
    /// time it took and the writes its pacing held. Watching a run changes
    /// nothing of it.
    #[test]
    fn replay_is_reproducible() {
        let cuts = vec![cut(1, 3, 3, CutScope::Both)];
        let links = LinkControls {
            latency_ms: 25,
            jitter_ms: 25,
            delivery_percent: 90,
        };
        let run = || execute(input(3, links, cuts.clone(), 21), |cluster| cluster);
        let (report, trace) = run();
        assert_eq!((report, trace.clone()), run());
        let watched = watched(input(3, links, cuts.clone(), 21));
        assert_eq!((watched.report, watched.trace), (report, trace));
    }

    /// What a partition holds decides how often the pacing holds its writes
    /// and how the report counts them, and is told by the partition's name.
    /// Every engine opens the reshare actor's journal, the Simplex journal,
    /// and the chain's partitions, and none the pacing does not know: a
    /// partition the DKG module names otherwise fails here.
    #[test]
    fn engines_open_the_partitions_the_pacing_knows() {
        let run = succeeded(input(1, CLEAN, Vec::new(), 2));
        for engine in 0..4 {
            assert_eq!(
                run.trace.opened(engine),
                vec![Partition::Journal, Partition::Consensus, Partition::Chain],
                "engine {engine}"
            );
        }
    }

    /// Run `count` sampled inputs, decoded the way libFuzzer's are, and sum
    /// what they came to. Every run is checked as libFuzzer's are.
    fn sample(count: usize) -> Sample {
        Sample::of(sample::each(count, |bytes| {
            let (report, trace) = execute(decode(bytes), |cluster| cluster);
            Sampled {
                outcome: report.outcome,
                failed: report.counts.completed > 0 && report.counts.successes == 0,
                crashes: report.restarts.crashes,
                paced: report.restarts.paced,
                overlaps: trace.overlaps(),
            }
        }))
    }

    /// Whatever the input, no two identities are impaired at once.
    #[test]
    fn sampled_inputs_impair_one_identity_at_a_time() {
        let sample = sample(24);
        assert_eq!(sample.overlapping, Vec::<usize>::new());
        assert!(sample.crashes > 0, "{sample:?}");
    }

    /// The same over a sample large enough to hold the schedules in which
    /// the window of one crash reaches back past the outage before it, and
    /// in which crashes do drop held writes.
    #[test]
    #[ignore = "runs 1,500 inputs"]
    fn large_sample_impairs_one_identity_at_a_time() {
        let sample = sample(1_500);
        assert_eq!(sample.overlapping, Vec::<usize>::new());
        assert!(sample.paced.crashes > 0, "{sample:?}");
    }

    #[test]
    fn landing_follows_the_processed_height() {
        // Heights 1 to 15 are the dealing window, 16 the midpoint, and 31
        // the final block.
        let landing = |processed| position(processed, LAST).1;
        assert_eq!(landing(0), Landing::Dealing);
        assert_eq!(landing(14), Landing::Dealing);
        assert_eq!(landing(15), Landing::Inclusion);
        assert_eq!(landing(30), Landing::Inclusion);
        assert_eq!(landing(31), Landing::Finished);
        assert_eq!(landing(40), Landing::Finished);
    }

    /// A fault a negative control plants at the boundary the oracle
    /// observes.
    #[derive(Clone, Copy)]
    enum Plant {
        /// Close the channels of this identity's engine once it has started,
        /// so that the engine ends on its own.
        Sever(usize),
        /// Panic in a task of this identity's engine.
        EnginePanic(usize),
        /// Panic in the harness, on its root task.
        HarnessPanic,
        /// Replace the first report of every engine that reported twice
        /// with a failure.
        Rewrite,
        /// Replace the only report of this identity's engine with a failure.
        Disagree(usize),
        /// Give the first identity the share the second holds.
        Swap(usize, usize),
        /// Give this identity a share of an output a trusted dealer dealt.
        Forge(usize),
        /// Have the first identity block the second.
        Block(usize, usize),
    }

    /// The cluster of real engines with one fault planted.
    struct Planted {
        cluster: Cluster,
        plant: Plant,
    }

    impl Stack for Planted {
        async fn start(&mut self, index: usize) -> Handle<()> {
            let handle = self.cluster.start(index).await;
            match self.plant {
                Plant::Sever(victim) if victim == index => {
                    // Registering a channel again closes the receiver the
                    // engine holds.
                    let participant = &self.cluster.participants[index];
                    drop(stack::register(&self.cluster.oracle, participant).await);
                }
                Plant::EnginePanic(victim) if victim == index => {
                    let context = self.cluster.context.child("planted");
                    drop(EngineContext::new(context, index).spawn(|_| async { panic!("planted") }));
                }
                _ => {}
            }
            handle
        }

        fn crashing(&mut self, index: usize) {
            assert!(
                !matches!(self.plant, Plant::HarnessPanic),
                "planted in the harness"
            );
            self.cluster.crashing(index);
        }

        fn follows(&self) -> bool {
            self.cluster.follows()
        }

        async fn settled(&mut self, absent: &[bool]) {
            self.cluster.settled(absent).await;
            match self.plant {
                Plant::Rewrite => {
                    for node in &self.cluster.nodes {
                        let mut reports = node.reports.lock();
                        if reports.len() > 1 {
                            reports[0].1 = Ending::Failure;
                        }
                    }
                }
                Plant::Disagree(engine) => {
                    let mut reports = self.cluster.nodes[engine].reports.lock();
                    if reports.len() == 1 {
                        reports[0].1 = Ending::Failure;
                    }
                }
                Plant::Swap(holder, other) => {
                    if let Some(share) = self.cluster.secrets[other].share(Epoch::zero()) {
                        self.cluster.secrets[holder].plant(Epoch::zero(), share);
                    }
                }
                Plant::Forge(holder) => {
                    let (_, shares) = deal::<MockGroup, _, N3f1>(
                        TestRng::new(1),
                        Mode::NonZeroCounter,
                        self.cluster.committee.clone(),
                    )
                    .expect("a trusted deal must succeed");
                    let share = shares
                        .get_value(&self.cluster.participants[holder])
                        .expect("every identity is dealt a share")
                        .clone();
                    self.cluster.secrets[holder].plant(Epoch::zero(), share);
                }
                Plant::Block(blocker, blocked) => {
                    let participants = &self.cluster.participants;
                    let mut control = self.cluster.oracle.control(participants[blocker].clone());
                    block!(control, participants[blocked].clone(), "planted block");
                }
                _ => {}
            }
        }
    }

    /// Run `input` with `plant` planted.
    fn run_planted(input: DkgBootstrapRestartsFuzzInput, plant: Plant) -> BootstrapRestartsReport {
        execute(input, |cluster| Planted { cluster, plant }).0
    }

    /// Run the input of [`engine_restarted_after_the_ceremony_reports_it_again`],
    /// on which the ceremony succeeds and engine 3 reports twice, with
    /// `plant` planted.
    fn planted(plant: Plant) -> BootstrapRestartsReport {
        run_planted(input(1, CLEAN, Vec::new(), 2), plant)
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped before the run ended")]
    fn engine_that_stops_on_its_own_is_rejected() {
        planted(Plant::Sever(2));
    }

    /// No identity is compromised here, so a panic of any engine is a
    /// violation, whatever it says.
    #[test]
    #[should_panic(expected = "I8 violated: correct engine 1 panicked")]
    fn engine_panic_is_rejected() {
        planted(Plant::EnginePanic(1));
    }

    #[test]
    #[should_panic(expected = "I8 violated: the run's root task panicked")]
    fn harness_panic_is_rejected() {
        planted(Plant::HarnessPanic);
    }

    #[test]
    #[should_panic(expected = "I1 violated: engine 3 reported different results for the \
                               ceremony of epoch 0 across restarts")]
    fn report_that_changes_across_a_restart_is_rejected() {
        planted(Plant::Rewrite);
    }

    #[test]
    #[should_panic(expected = "I1 violated: engines 0 and 1 disagree on the ceremony of epoch 0")]
    fn report_that_differs_between_engines_is_rejected() {
        planted(Plant::Disagree(1));
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 0 at index")]
    fn share_of_another_identity_is_rejected() {
        planted(Plant::Swap(1, 2));
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 2 holds for epoch 0 does not match")]
    fn share_of_another_output_is_rejected() {
        planted(Plant::Forge(2));
    }

    #[test]
    #[should_panic(
        expected = "I6 violated: engine 2 holds a share of epoch 0 although the \
                               ceremony failed"
    )]
    fn share_after_a_failed_ceremony_is_rejected() {
        run_planted(failing(), Plant::Forge(2));
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_is_rejected() {
        planted(Plant::Block(0, 3));
    }
}

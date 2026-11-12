//! The reshare restart driver: five correct identities, no byzantine
//! behaviour.
//!
//! The run starts from an output a trusted dealer deals to the first
//! committee, four of the five identities, and reshares it for the number of
//! epochs the input selects, among the committees the input schedules, as the
//! reshare Twins driver does. Every identity runs one real reshare engine and
//! the only faults are environmental: the engines are crashed and restarted
//! on a schedule drawn from the tape, and the links among them delay, lose,
//! and for a while cut off what they carry, as the input directs.
//!
//! The secret stores and the engines' storage are paced (see
//! [`pacing`](super::pacing)): some of the writes an engine makes shortly
//! before one of its crashes are held, so the crash can fall between two
//! writes the engine makes one after the other.
//!
//! A restart keeps the identity's storage partitions and its secret store
//! (see [`reshare_cluster`](super::reshare_cluster)). The engine it brings
//! back reads the epoch it is in from the chain it stored, registers that
//! epoch's scheme again from the share its secret store holds, replays its
//! journal, resumes its dealer and its player, and re-enters the ceremony
//! wherever the crash left it. An engine that was down while its peers ended
//! an epoch learns the end of the ceremony from the chain, and derives its
//! share of the new output from the dealings it stored and the shares the
//! dealer logs reveal.
//!
//! The run ends when the schedule has been played out, the latest instance
//! of every engine has entered the epoch after the last one the input
//! selected, and every engine a restart brought back has applied a block
//! since that restart or the environment's bound on that wait has passed;
//! when an engine stops on its own; or when the bounded timeout expires. An
//! event of the schedule that is still to come once every engine that can
//! make progress has entered that epoch runs at once instead of at its time
//! (see [`environment`]). The invariants are checked over every boundary any
//! engine reached, on what every instance of every engine reported and on
//! every share every secret store ever held. Because every identity is
//! correct, they are checked over all five, and no panic is tolerated.

use super::{
    DkgReshareRestartsFuzzInput, Outcome, PublicKey, RESHARE_IDENTITIES, RESHARE_RUN_TIMEOUT,
    TRACKED_PEER_SETS,
    environment::{self, Program, Stack},
    invariants::{self, Instance, Reshare, ReshareCounts},
    pacing::{PacedCounts, Trace},
    reshare_cluster::{Cluster, ReshareRestartCounts, Session},
    runner::{self, Report},
    signers,
};
use crate::stateful::runner::network_with;
use commonware_runtime::deterministic;
use std::{fmt, time::Duration};

/// Label the driver reports under.
const TARGET: &str = "glue-dkg-reshare-restarts";

/// What one reshare restart run observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReshareRestartsReport {
    /// Why the run stopped.
    pub outcome: Outcome,
    /// Epochs the run was asked to complete.
    pub asked: u8,
    /// How much each check compared.
    pub counts: ReshareCounts,
    /// Registrations of an epoch the engine holds a share for, each required
    /// to carry that share under I2.
    pub signers: usize,
    /// What the restart schedule did.
    pub restarts: ReshareRestartCounts,
    /// How the writes the pacing held ended: how many crashes dropped one,
    /// and what each dropped write left behind.
    pub paced: PacedCounts,
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

impl fmt::Display for ReshareRestartsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} asked={} epochs={} correct_nodes={} boundaries={} successes={} \
             failures={} agreements={} registrations={} signers={} shares={} players={} \
             reconstructions={} continuities={} isolations={} carried={} kept={} blocks={} \
             crashes={} restarts={} dealing={} inclusion={} boundary={} finished={} resumed={} \
             across={} repeated={} {} followed={} expired={} after_ms={} after_blocks={} \
             elapsed_ms={}",
            self.outcome,
            self.asked,
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
            self.counts.kept,
            self.counts.blocks,
            self.restarts.crashes,
            self.restarts.restarts,
            self.restarts.dealing,
            self.restarts.inclusion,
            self.restarts.boundary,
            self.restarts.finished,
            self.restarts.resumed,
            self.restarts.across,
            self.restarts.repeated,
            self.paced,
            self.followed,
            self.expired,
            self.after.as_millis(),
            self.after_blocks,
            self.elapsed.as_millis(),
        )
    }
}

impl Report for ReshareRestartsReport {
    fn measured(&self) -> bool {
        self.counts.boundaries > 0
    }
}

/// libFuzzer entry point.
pub fn fuzz_dkg_reshare_restarts(input: DkgReshareRestartsFuzzInput) {
    runner::fuzz(input.raw_bytes.clone(), input, run_dkg_reshare_restarts);
}

/// Run the selected epochs of resharing under one restart schedule and one
/// set of link conditions and return what the run measured.
///
/// A run is fully determined by its input.
pub fn run_dkg_reshare_restarts(input: DkgReshareRestartsFuzzInput) -> ReshareRestartsReport {
    execute(input, |cluster| cluster).0
}

/// Run `input` over the stack `wrap` makes of the cluster of real engines.
/// Returns what the run measured, what its pacing did, and the records the
/// oracle judged it by.
///
/// libFuzzer runs the cluster itself. A test wraps it to plant a fault at the
/// boundary the oracle observes, or to observe what a restart finds.
fn execute<S: Stack>(
    input: DkgReshareRestartsFuzzInput,
    wrap: impl FnOnce(Cluster) -> S,
) -> (ReshareRestartsReport, Trace, Reshare) {
    let entropy = input.raw_bytes.clone();
    let asked = input.session.epochs;
    let (observed, panics) = runner::execute(entropy.clone(), |context| {
        run(context, input, entropy, wrap)
    });

    // Measurement point, outside the runtime so a violation is never caught.
    // No identity is compromised, so no panic is tolerated.
    invariants::check_panics(&panics, &[]);
    let crashes = invariants::check_instances_running(&observed.instances);
    let counts = invariants::check_reshare(&observed.reshare, &observed.blocked);
    let signers = invariants::check_registered_shares(&observed.reshare);
    let report = ReshareRestartsReport {
        outcome: observed.outcome,
        asked,
        counts,
        signers,
        restarts: ReshareRestartCounts {
            crashes,
            ..observed.restarts
        },
        paced: observed.paced.counts(),
        followed: observed.followed,
        expired: observed.expired,
        after: observed.after,
        after_blocks: observed.after_blocks,
        elapsed: observed.elapsed,
    };
    (report, observed.paced, observed.reshare)
}

/// What a run observed, to be checked once the runtime has stopped.
struct Observations {
    outcome: Outcome,
    /// What every instance of every engine reported, and every share every
    /// secret store held.
    reshare: Reshare,
    /// Every engine instance the run started.
    instances: Vec<Instance>,
    blocked: Vec<(PublicKey, PublicKey)>,
    /// What the driver saw of the schedule. The crashes the oracle counts
    /// are filled in at the measurement point.
    restarts: ReshareRestartCounts,
    /// What the pacing did.
    paced: Trace,
    /// What the end of the run saw of the engines a restart brought back
    /// (see [`ReshareRestartsReport`]).
    followed: usize,
    expired: usize,
    after: Duration,
    after_blocks: u64,
    elapsed: Duration,
}

async fn run<S: Stack>(
    mut context: deterministic::Context,
    input: DkgReshareRestartsFuzzInput,
    entropy: Vec<u8>,
    wrap: impl FnOnce(Cluster) -> S,
) -> Observations {
    let session = Session::deal(&mut context, signers(RESHARE_IDENTITIES), &input.session);
    let participants = session.participants.clone();
    let link = input.environment.links.link();
    let program = Program::new(&input.environment, entropy, participants.len());
    let oracle = network_with(&context, &participants, link.clone(), TRACKED_PEER_SETS).await;

    // The oracle reads what the engines report and hold, whatever a test
    // makes of the cluster.
    let cluster = Cluster::new(&context, oracle.clone(), session).paced(&program);
    let view = cluster.view();
    let mut stack = wrap(cluster);
    let played = environment::play(
        &context,
        &oracle,
        &participants,
        link,
        program,
        &mut stack,
        RESHARE_RUN_TIMEOUT,
    )
    .await;

    // Every identity is correct, so every engine is in the records.
    let blocked = runner::blocked(&oracle).await;
    let last = played.last_restarted().copied();
    Observations {
        outcome: played.outcome,
        reshare: view.reshare(),
        blocked,
        restarts: view.counts(),
        followed: played.followed.len(),
        expired: played.expired(),
        after: last.map_or(Duration::ZERO, |last| last.lasted),
        after_blocks: last.map_or(0, |last| last.blocks),
        instances: played.instances,
        paced: played.paced,
        elapsed: played.elapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        COMMITTEE, Cut, CutScope, EnvironmentControls, Info, LinkControls, MockGroup, Rotation,
        context::EngineContext,
        environment::{CUT_STEP, Event, FOLLOW, Landing},
        fixtures::{
            self, CLEAN, LOSSY, OUTSIDER, ROTATE, Retaining, STAY, Sample, Sampled, Watched, cut,
            decode, journal, sample, tape, votes,
        },
        pacing::{Change, Operation, Partition, Secret, Stage},
        reshare_input::ROTATIONS,
        reshare_restarts_input::SessionControls,
        reshare_stack,
        schedule::Schedule,
        scheme::Registration,
        store::Secrets,
    };
    use commonware_codec::{Copying, Encode as _, Read as _};
    use commonware_consensus::types::Epoch;
    use commonware_cryptography::bls12381::{
        dkg::feldman_desmedt::{Output, deal},
        primitives::sharing::{Mode, ModeVersion},
    };
    use commonware_glue::dkg::{
        SecretStore as _,
        types::{EpochOutcome, SchemeInfo},
    };
    use commonware_p2p::{Blocker as _, block};
    use commonware_runtime::{Handle, Spawner as _, Supervisor as _};
    use commonware_utils::{N3f1, TestRng, sync::Mutex};
    use std::{ops::Range, sync::Arc};

    fn input(
        epochs: u8,
        rotations: [Rotation; ROTATIONS],
        restarts: u8,
        links: LinkControls,
        cuts: Vec<Cut>,
        seed: u16,
    ) -> DkgReshareRestartsFuzzInput {
        DkgReshareRestartsFuzzInput {
            session: SessionControls {
                epochs,
                sharing_mode: Mode::NonZeroCounter,
                outsider: OUTSIDER,
                rotations,
            },
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
    fn schedule(input: &DkgReshareRestartsFuzzInput) -> Vec<(u128, Event)> {
        let identities = RESHARE_IDENTITIES as usize;
        fixtures::schedule(&input.environment, &input.raw_bytes, identities)
    }

    /// What an identity had retained when a restart of its engine began, and
    /// what the restart found of the run.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(in crate::dkg) struct Retained {
        engine: usize,
        /// The epoch the engine resumes in, and where its crash found it.
        epoch: Epoch,
        landing: Landing,
        /// Whether its secret store held its dealer seed for that epoch.
        seed: bool,
        /// How many private dealings of that epoch's ceremony its secret
        /// store held.
        dealings: usize,
        /// Whether its secret store held its share for that epoch.
        share: bool,
        /// Whether its secret store held its share for the epoch after that
        /// one, which is its share of the output of that epoch's ceremony.
        next_share: bool,
        /// The earliest epoch its secret store held a dealer seed for.
        oldest: Option<Epoch>,
        /// The durable length of the reshare actor's journal.
        journal: u64,
        /// The durable length of the journal its Simplex engine kept for
        /// that epoch, which holds the votes the engine cast in it.
        votes: u64,
        /// How many schemes the instances of its engine had registered.
        registered: usize,
        /// The latest epoch whose scheme the engine of another identity had
        /// registered.
        peers: Epoch,
    }

    impl Retaining for Cluster {
        type Retained = Retained;

        async fn retained(&mut self, index: usize) -> Retained {
            let journal = journal(&self.context, index).await;
            let node = &self.nodes[index];
            let (epoch, landing) = node.crashed.expect("a restart follows a crash");
            let votes = votes(&self.context, index, epoch).await;
            let secrets = &node.secrets;
            let peers = self
                .nodes
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .flat_map(|(_, node)| node.records.registrations())
                .map(|(registered, _)| registered)
                .max()
                .unwrap_or_default();
            Retained {
                engine: index,
                epoch,
                landing,
                seed: secrets.seeded(epoch),
                dealings: secrets.dealings(epoch),
                share: secrets.share(epoch).is_some(),
                next_share: secrets.share(epoch.next()).is_some(),
                oldest: (0..=epoch.next().get())
                    .map(Epoch::new)
                    .find(|held| secrets.seeded(*held)),
                journal,
                votes,
                registered: node.records.registrations().len(),
                peers,
            }
        }
    }

    /// One run of an input over the watched cluster.
    struct Run {
        input: DkgReshareRestartsFuzzInput,
        report: ReshareRestartsReport,
        /// What the pacing did.
        trace: Trace,
        /// What each restart found, in the order of the restarts.
        retained: Vec<Retained>,
        /// What every instance of every engine reported and every share
        /// every secret store held, as the oracle read them.
        reshare: Reshare,
    }

    impl Run {
        /// The epoch after the last one the run was asked to complete.
        fn last(&self) -> Epoch {
            Epoch::new(u64::from(self.input.session.epochs))
        }
    }

    /// Run `input` over the watched cluster, and assert that no two
    /// identities were impaired at once.
    fn watched(input: DkgReshareRestartsFuzzInput) -> Run {
        let retained = Arc::new(Mutex::new(Vec::new()));
        let (report, trace, reshare) = execute(input.clone(), |cluster| {
            Watched::new(cluster, Arc::clone(&retained))
        });
        println!("{report}");
        assert_eq!(trace.overlaps(), 0, "{:?}", trace.impairments());
        let retained = retained.lock().clone();
        Run {
            input,
            report,
            trace,
            retained,
            reshare,
        }
    }

    /// Whether `run` completed with every ceremony it reached successful.
    fn completed(run: &Run) -> bool {
        run.report.outcome == Outcome::Completed && run.report.counts.failures == 0
    }

    /// Assert that the checks of `run` were not vacuous: every ceremony the
    /// run was asked for succeeded at all five engines, and every check
    /// compared them at every boundary.
    ///
    /// The chain goes on while the schedule is played out, so a run may
    /// reach, and check, more boundaries than it was asked for.
    fn assert_succeeded(run: &Run) {
        let asked = usize::from(run.input.session.epochs);
        let report = run.report;
        assert_eq!(report.outcome, Outcome::Completed, "{report}");
        let counts = report.counts;
        assert_eq!(counts.correct_nodes, 5, "{report}");
        assert_eq!(counts.failures, 0, "{report}");
        assert_eq!(counts.blocks, 0, "{report}");
        assert!(counts.epochs >= asked, "{report}");
        assert_eq!(counts.successes, counts.epochs, "{report}");
        assert_eq!(counts.continuities, counts.epochs, "{report}");
        assert!(counts.boundaries >= 5 * asked, "{report}");
        assert!(counts.agreements >= 4 * asked, "{report}");

        // Every engine registers the first epoch and each one it enters, and
        // the four of each committee register as signers.
        assert!(counts.registrations >= 5 * (asked + 1), "{report}");
        assert!(report.signers >= 4 * (asked + 1), "{report}");
        assert!(counts.shares >= 4 * (asked + 1), "{report}");
        assert!(counts.players >= 4 * asked, "{report}");

        // Four holders and three required: four subsets reconstruct each
        // output, and forty-eight sets mix two outputs.
        assert!(counts.reconstructions >= 4 * (asked + 1), "{report}");
        assert!(counts.isolations >= 48 * asked, "{report}");
    }

    /// Run one fixed input and assert that its checks were not vacuous.
    fn succeeded(input: DkgReshareRestartsFuzzInput) -> Run {
        let run = watched(input);
        assert_succeeded(&run);
        run
    }

    /// Lists, for each seed of a range, the schedule of the input over
    /// clean links and an unchanging committee, what its run came to, the
    /// held writes each crash dropped, and what each restart found. The
    /// fixed inputs of the tests here were chosen from this listing.
    ///
    /// `SURVEY` names the number of epochs, the number of restarts, the
    /// seeds, and optionally the identity outside the first committee, as
    /// in `1:1:0..300` and `1:1:0..300:0`. `SURVEY_CRASH` keeps only the
    /// seeds whose first crash is due in a range of milliseconds, as in
    /// `3600..3601`, and `SURVEY_LATENCY` runs them over links of another
    /// latency, in milliseconds.
    #[test]
    #[ignore = "a listing to choose fixed inputs from"]
    fn survey() {
        let variable = |name: &str| std::env::var(name).ok();
        let range = |range: &str| -> (u64, u64) {
            let (from, to) = range.split_once("..").expect("from..to");
            (from.parse().expect("from"), to.parse().expect("to"))
        };
        let survey = variable("SURVEY").unwrap_or_else(|| "1:1:0..300".into());
        let mut fields = survey.split(':');
        let mut field = || fields.next().expect("epochs:restarts:from..to");
        let epochs: u8 = field().parse().expect("epochs");
        let restarts: u8 = field().parse().expect("restarts");
        let (from, to) = range(field());
        let outsider: u8 = fields.next().map_or(OUTSIDER, |outsider| {
            outsider.parse().expect("the outside identity")
        });
        let crash = variable("SURVEY_CRASH").map(|crash| range(&crash));
        let links = LinkControls {
            latency_ms: variable("SURVEY_LATENCY").map_or(CLEAN.latency_ms, |latency| {
                latency.parse().expect("a latency in milliseconds")
            }),
            ..CLEAN
        };
        for seed in from..to {
            let seed = u16::try_from(seed).expect("a seed is sixteen bits");
            let mut input = input(epochs, STAY, restarts, links, Vec::new(), seed);
            input.session.outsider = outsider;
            let schedule = schedule(&input);
            let due = u64::try_from(schedule[0].0).expect("a crash is due within the run");
            if crash.is_some_and(|(from, to)| !(from..to).contains(&due)) {
                continue;
            }
            let retained = Arc::new(Mutex::new(Vec::new()));
            let (report, trace, _) = execute(input, |cluster| {
                Watched::new(cluster, Arc::clone(&retained))
            });
            let dropped: Vec<_> = (0..RESHARE_IDENTITIES as usize)
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

    /// The seeds a test looks for its scenario among.
    const SEEDS: Range<u16> = 0..200;

    /// How many of those seeds are run at a time, each on its own thread.
    const ABREAST: usize = 4;

    /// The first run, over the inputs `input` makes of `seeds`, that shows
    /// a scenario, with what `shows` makes of it (see [`fixtures::first`]).
    fn first<T: Send>(
        seeds: Range<u16>,
        input: impl Fn(u16) -> DkgReshareRestartsFuzzInput + Sync,
        shows: impl Fn(&Run) -> Option<T> + Sync,
    ) -> (Run, T) {
        let (seed, run, shown) = fixtures::first(seeds, ABREAST, |seed| {
            let run = watched(input(seed));
            let shown = shows(&run)?;
            Some((seed, run, shown))
        });
        println!("seed {seed} shows the scenario");
        (run, shown)
    }

    /// The first run among [`SEEDS`], over clean links and an unchanging
    /// committee, for `epochs` epochs and under `restarts` restarts, that
    /// shows a scenario.
    fn first_clean<T: Send>(
        epochs: u8,
        restarts: u8,
        shows: impl Fn(&Run) -> Option<T> + Sync,
    ) -> (Run, T) {
        first(
            SEEDS,
            |seed| input(epochs, STAY, restarts, CLEAN, Vec::new(), seed),
            shows,
        )
    }

    /// What the one restart of `run` found, if `run` completed, with every
    /// ceremony successful, after one crash and its restart.
    fn restarted(run: &Run) -> Option<&Retained> {
        let [found] = &run.retained[..] else {
            return None;
        };
        (completed(run) && run.report.restarts.crashes == 1).then_some(found)
    }

    /// Schemes an engine registered, each with its epoch, in order.
    type Registered = [(Epoch, Registration)];

    /// The schemes the engine `found` describes registered before the
    /// restart and after it.
    fn registered<'a>(run: &'a Run, found: &Retained) -> (&'a Registered, &'a Registered) {
        run.reshare.nodes[found.engine]
            .registered
            .split_at(found.registered)
    }

    /// The latest scheme among `registered` that is the scheme of `epoch`.
    fn registration(registered: &Registered, epoch: Epoch) -> Option<&Registration> {
        registered
            .iter()
            .rev()
            .find(|(registered, _)| *registered == epoch)
            .map(|(_, registration)| registration)
    }

    /// How many distinct shares the secret store of `engine` ever held for
    /// `epoch`.
    fn shares(run: &Run, engine: usize, epoch: Epoch) -> usize {
        run.reshare.nodes[engine]
            .shares
            .iter()
            .filter(|(stored, _)| *stored == epoch)
            .count()
    }

    /// Assert that the engine `found` describes came back as the signer it
    /// was: the first scheme it registered after the restart is the scheme
    /// of the epoch it resumed in, and the one it had registered for that
    /// epoch before the crash, with its share.
    fn assert_registered_again(run: &Run, found: &Retained) {
        let (before, after) = registered(run, found);
        let again = after.first().expect("a restarted engine registers");
        assert_eq!(again.0, found.epoch, "{found:?}");
        assert!(
            matches!(again.1, SchemeInfo::Signer { .. }),
            "{found:?}: {again:?}"
        );
        assert_eq!(
            registration(before, found.epoch),
            Some(&again.1),
            "{found:?}"
        );
    }

    /// Assert that the engine `found` describes, once restarted, entered
    /// `epoch` as a signer, with one share for that epoch on its record.
    fn assert_entered(run: &Run, found: &Retained, epoch: Epoch) {
        let (_, after) = registered(run, found);
        let entered = registration(after, epoch);
        assert!(
            matches!(entered, Some(SchemeInfo::Signer { .. })),
            "{found:?}: {entered:?}"
        );
        assert_eq!(shares(run, found.engine, epoch), 1, "{found:?}");
    }

    /// The engine is crashed while its marshal is in the dealing window and
    /// comes back before any of its peers has ended the ceremony. It reads
    /// the epoch from the chain it stored, registers the epoch's scheme
    /// again with the share its secret store kept, resumes its dealer from
    /// the seed it stored and its player from its journal, and the
    /// ceremony's result is checked at all five engines.
    #[test]
    fn crash_in_the_dealing_window_resumes_the_ceremony() {
        let (run, found) = first_clean(1, 1, |run| {
            restarted(run)
                .filter(|found| {
                    found.landing == Landing::Dealing && found.share && found.peers == found.epoch
                })
                .cloned()
        });
        assert_succeeded(&run);
        assert_eq!(
            run.report.restarts,
            ReshareRestartCounts {
                crashes: 1,
                restarts: 1,
                dealing: 1,
                resumed: 1,
                ..ReshareRestartCounts::default()
            }
        );
        assert!(found.seed, "{found:?}");
        assert_registered_again(&run, &found);
        assert_entered(&run, &found, found.epoch.next());
    }

    /// The engine is crashed after the midpoint, while dealer logs are being
    /// included, and re-enters the inclusion window before any peer has
    /// ended the ceremony.
    #[test]
    fn crash_in_the_inclusion_window_resumes_the_ceremony() {
        let (run, found) = first_clean(1, 1, |run| {
            restarted(run)
                .filter(|found| {
                    found.landing == Landing::Inclusion && found.share && found.peers == found.epoch
                })
                .cloned()
        });
        assert_succeeded(&run);
        assert_eq!(
            run.report.restarts,
            ReshareRestartCounts {
                crashes: 1,
                restarts: 1,
                inclusion: 1,
                resumed: 1,
                ..ReshareRestartCounts::default()
            }
        );
        assert_registered_again(&run, &found);
        assert_entered(&run, &found, found.epoch.next());
    }

    /// The engine is crashed in the first ceremony and is still down when
    /// its peers end it and enter the second epoch. It comes back while
    /// they are in the second ceremony, with the run still going: in the
    /// first epoch by its own chain, it learns the end of the first ceremony
    /// from the chain, derives its share of the second output, and joins the
    /// second ceremony. Both boundaries are checked at all five engines.
    #[test]
    fn engine_down_across_an_epoch_boundary_catches_up() {
        let second = Epoch::new(1);
        let (run, found) = first_clean(2, 1, |run| {
            restarted(run)
                .filter(|found| {
                    matches!(found.landing, Landing::Dealing | Landing::Inclusion)
                        && found.epoch == Epoch::zero()
                        && found.share
                        && found.peers == second
                })
                .cloned()
        });
        assert_succeeded(&run);
        let restarts = run.report.restarts;
        assert_eq!(
            (restarts.crashes, restarts.restarts, restarts.across),
            (1, 1, 1),
            "{restarts:?}"
        );
        assert_eq!(
            (restarts.resumed, restarts.repeated),
            (0, 0),
            "{restarts:?}"
        );

        // The restarted engine holds a share of both outputs and entered
        // both epochs with it.
        assert_registered_again(&run, &found);
        assert_entered(&run, &found, second);
        assert_entered(&run, &found, second.next());
        assert!(run.report.counts.boundaries >= 10, "{}", run.report);
        assert!(run.report.counts.players >= 8, "{}", run.report);
    }

    /// The engine is crashed in the dealing window and stays down while the
    /// other four end the ceremony and the run. Its restart is brought
    /// forward, it applies the rest of the epoch from the chain, and it
    /// derives a valid share of the new output although it was down when
    /// the ceremony ended.
    #[test]
    fn engine_that_misses_the_end_of_the_ceremony_derives_its_share_from_the_chain() {
        let (run, found) = first_clean(1, 1, |run| {
            restarted(run)
                .filter(|found| {
                    found.landing == Landing::Dealing && found.share && found.peers >= run.last()
                })
                .cloned()
        });
        assert_succeeded(&run);
        assert_eq!(
            run.report.restarts,
            ReshareRestartCounts {
                crashes: 1,
                restarts: 1,
                dealing: 1,
                across: 1,
                ..ReshareRestartCounts::default()
            }
        );

        // The share of the new output is not in the store when the engine
        // comes back, and it is there when the run ends.
        assert!(!found.next_share, "{found:?}");
        assert_registered_again(&run, &found);
        assert_entered(&run, &found, found.epoch.next());
    }

    /// The crash is due after the run's last epoch, so it runs as soon as
    /// every engine has registered the next epoch's scheme. It finds its
    /// engine at the boundary: the new share stored and the scheme
    /// registered, and the epoch's final block not yet recorded by its
    /// marshal. The restarted engine is back in the inclusion window: it
    /// registers the epoch it left again, applies the final block again,
    /// and registers the next epoch again, with the same share. Such a
    /// restart repeats a boundary: it is counted neither as re-entering a
    /// ceremony nor as an outage across a boundary.
    #[test]
    fn crash_between_the_new_share_and_the_final_block_repeats_the_boundary() {
        let (run, found) = first_clean(1, 1, |run| {
            restarted(run)
                .filter(|found| {
                    found.landing == Landing::Boundary && found.share && found.next_share
                })
                .cloned()
        });
        assert_succeeded(&run);
        assert_eq!(
            run.report.restarts,
            ReshareRestartCounts {
                crashes: 1,
                restarts: 1,
                boundary: 1,
                repeated: 1,
                ..ReshareRestartCounts::default()
            }
        );

        // The engine had registered the next epoch before the crash, and
        // registers it again with the share it had stored.
        let next = found.epoch.next();
        let (before, after) = registered(&run, &found);
        let ended = registration(before, next).expect("the engine had ended the ceremony");
        assert_registered_again(&run, &found);
        assert_entered(&run, &found, next);
        assert_eq!(registration(after, next), Some(ended), "{found:?}");
    }

    /// What the last restart of `run` found, if `run` completed, with every
    /// ceremony successful, after two crashes and their restarts, the
    /// second of which found its engine, a share holder, past the last
    /// epoch the run was asked for.
    fn restarted_past_the_last_epoch(run: &Run) -> Option<&Retained> {
        let [_, found] = &run.retained[..] else {
            return None;
        };
        (completed(run)
            && run.report.restarts.crashes == 2
            && found.landing == Landing::Finished
            && found.share)
            .then_some(found)
    }

    /// The second crash finds its engine past the run's last boundary. The
    /// engine that comes back registers the epoch it is in from the share
    /// it stored.
    #[test]
    fn engine_crashed_after_the_last_epoch_registers_its_scheme_again() {
        let (run, found) = first_clean(1, 2, |run| restarted_past_the_last_epoch(run).cloned());
        assert_succeeded(&run);
        let restarts = run.report.restarts;
        assert_eq!(
            (restarts.crashes, restarts.restarts),
            (2, 2),
            "{restarts:?}"
        );
        assert!(restarts.finished >= 1, "{restarts:?}");
        assert!(found.epoch >= run.last(), "{found:?}");
        assert_registered_again(&run, &found);
    }

    /// The engine restarted past the run's last boundary registers the epoch
    /// it is in as it sets itself up, which is all the cluster waits for of
    /// it. The run goes on until that engine has applied a block of the
    /// chain since its restart, well inside the bound on that wait.
    #[test]
    fn engine_restarted_after_the_last_epoch_is_followed_to_its_next_block() {
        let (run, found) = first_clean(1, 2, |run| {
            restarted_past_the_last_epoch(run)
                .filter(|_| run.report.expired == 0)
                .cloned()
        });
        assert_succeeded(&run);
        let report = run.report;
        assert!(found.epoch >= run.last(), "{found:?}");

        // The second restart is the last, and its engine is the one the end
        // of the run waited for.
        assert!(report.followed >= 1, "{report}");
        assert!(report.after_blocks >= 1, "{report}");
        assert!(report.after < FOLLOW, "{report}");
    }

    /// Full schedules over three epochs in which the outside identity joins
    /// before every ceremony: every crash is followed by its restart, and
    /// the crashes and the restarts land in every part of a run.
    #[test]
    fn repeated_restarts_over_rotating_committees_hold_invariants() {
        let mut landed = ReshareRestartCounts::default();
        let mut paced = PacedCounts::default();
        let everywhere = |landed: &ReshareRestartCounts, paced: &PacedCounts| {
            let landings = [
                landed.dealing,
                landed.inclusion,
                landed.boundary,
                landed.finished,
                landed.resumed,
                landed.across,
                landed.repeated,
            ];

            // Some of the crashes fell inside a held write, of the DKG
            // module's own state among them.
            landings.iter().all(|landings| *landings > 0)
                && paced.crashes > 0
                && paced.before > 0
                && paced.durable > 0
                && paced.dkg_before + paced.dkg_durable > 0
        };
        for seed in SEEDS {
            let run = watched(input(3, ROTATE, 4, CLEAN, Vec::new(), seed));
            if !completed(&run) {
                continue;
            }
            assert_succeeded(&run);
            let report = run.report;
            assert_eq!(report.restarts.crashes, 4, "{report}");
            assert_eq!(report.restarts.restarts, 4, "{report}");
            paced += report.paced;
            landed.dealing += report.restarts.dealing;
            landed.inclusion += report.restarts.inclusion;
            landed.boundary += report.restarts.boundary;
            landed.finished += report.restarts.finished;
            landed.resumed += report.restarts.resumed;
            landed.across += report.restarts.across;
            landed.repeated += report.restarts.repeated;
            if everywhere(&landed, &paced) {
                return;
            }
        }
        panic!("the schedules of {SEEDS:?} leave a part of a run out: {landed:?} {paced:?}");
    }

    /// The write that stores the private half of a dealing.
    const PRIVATE_HALF: Operation = Operation::Secret(Secret::Dealing);

    /// The write that stores a share.
    const SHARE: Operation = Operation::Secret(Secret::Share);

    /// The write that removes the secrets of old epochs.
    const PRUNE: Operation = Operation::Secret(Secret::Prune);

    /// The identity whose engine is started last. Its first writes are the
    /// only ones an engine makes at its first start that may be held: a
    /// write is held only while every identity is up. It is a player of the
    /// first ceremony when another identity is the outside one.
    const LAST_STARTED: usize = RESHARE_IDENTITIES as usize - 1;

    /// What the one restart of `run` found.
    fn found(run: &Run) -> &Retained {
        let [found] = &run.retained[..] else {
            panic!("the run has one restart: {:?}", run.retained);
        };
        found
    }

    /// Run the fixed input of a state test: `epochs` epochs over clean links
    /// and an unchanging committee that `outsider` is outside of, under one
    /// restart. Its ceremonies succeed.
    ///
    /// Which write a crash drops depends on which writes its engine made in
    /// the crash's window and on the draws the tape gives them, so these
    /// tests fix their inputs, as those of the bootstrap restart driver do.
    /// Each seed is taken from a listing of [`survey`], which finds another
    /// if the timing of a run changes. Three of the states do not depend on
    /// how long a block takes, and their runs show them over links of 10 ms,
    /// of 14 ms, and of 20 ms alike: the two splits of a dealing arise as
    /// the engine of the last identity starts, and the share that is stored
    /// unseen is held from the final block until a crash that is due well
    /// after it. The other three need their crash within a fraction of a
    /// second of an epoch's final block, and their seeds show them over the
    /// links of [`CLEAN`] only.
    fn pinned(epochs: u8, outsider: u8, seed: u16) -> Run {
        let mut input = input(epochs, STAY, 1, CLEAN, Vec::new(), seed);
        input.session.outsider = outsider;
        succeeded(input)
    }

    /// Assert that the one crash of `run` dropped the held writes `dropped`,
    /// in the order their holds began, and that no other write was held.
    fn assert_dropped(run: &Run, dropped: &[(Operation, Stage)]) {
        let found = found(run);
        assert_eq!(
            run.trace.dropped(found.engine),
            dropped,
            "the seed does not show its state, take another from the survey: {found:?}"
        );
        assert_eq!(run.trace.holds().len(), dropped.len());
    }

    /// A dealing split by the crash: its journal entry without its private
    /// half. The reshare actor writes the two halves of a dealing it
    /// accepts at once. The write of the private half is held before it is
    /// applied, the journal entry is written and synced meanwhile, and the
    /// crash drops the held write, so the journal names a dealing the
    /// secret store does not hold. The dealing is the engine's own, which it
    /// records as it starts. The engine that comes back drops it when it
    /// replays its journal, deals it to itself again, and ends the ceremony
    /// with a valid share.
    ///
    /// The seed is the first of the seeds 0 to 11999 on which, in the
    /// listing of [`survey`] for `1:1:0..12000:0`, the crash dropped that
    /// write and no other while the secret store held no dealing.
    #[test]
    fn crash_that_leaves_a_journaled_dealing_without_its_private_half_is_survived() {
        let run = pinned(1, 0, 59);
        let found = found(&run);
        assert_eq!(found.engine, LAST_STARTED);

        // No other write was held, so the journal entry was made.
        assert_dropped(&run, &[(PRIVATE_HALF, Stage::Before)]);

        // What the crash left: a journal that holds an entry, and no
        // private half.
        assert_eq!(
            (found.landing, found.dealings),
            (Landing::Dealing, 0),
            "{found:?}"
        );
        assert!(found.journal > 0, "{found:?}");
        assert_registered_again(&run, found);
        assert_entered(&run, found, found.epoch.next());
    }

    /// The other split of a dealing: its private half without its journal
    /// entry. The write of the private half is held after it is applied and
    /// the write of the journal entry before it is applied, and the crash
    /// drops both, so the secret store holds a dealing that no journal
    /// entry names, although the engine never saw it stored. The engine that
    /// comes back finds a private half it has no record of, deals the
    /// dealing to itself again, and the ceremony's result is checked at all
    /// five.
    ///
    /// The seed is the first of the same listing whose crash dropped these
    /// two writes and no other while the journal was empty.
    #[test]
    fn crash_that_leaves_a_private_half_without_its_journal_entry_is_survived() {
        let run = pinned(1, 0, 1035);
        let found = found(&run);
        assert_eq!(found.engine, LAST_STARTED);
        assert_dropped(
            &run,
            &[
                (PRIVATE_HALF, Stage::After),
                (
                    Operation::Blob(Partition::Journal, Change::Write { synced: false }),
                    Stage::Before,
                ),
            ],
        );

        // The two writes were in flight together, until the crash.
        let [private, journal] = run.trace.holds() else {
            panic!("two writes were held: {:?}", run.trace.holds());
        };
        assert!(private.from <= journal.from && journal.from < private.until.unwrap());
        assert_eq!(private.until, journal.until);

        // What the crash left: the private half, and nothing in the journal.
        assert_eq!(
            (found.landing, found.dealings, found.journal),
            (Landing::Dealing, 1, 0),
            "{found:?}"
        );
        assert_registered_again(&run, found);
        assert_entered(&run, found, found.epoch.next());
    }

    /// The engine has derived its share of the new output from the epoch's
    /// final block, and the write that stores it is held before it is
    /// applied. The crash drops it, so the engine that comes back holds no
    /// share of the new output: it is in the inclusion window again,
    /// applies the final block again, and derives and stores the share
    /// anew.
    ///
    /// The seed is the first of the seeds 0 to 2999 on which, in the
    /// listing of [`survey`] for `1:1:0..3000`, the crash dropped that write
    /// and no other.
    #[test]
    fn crash_before_the_new_share_is_stored_is_survived() {
        let run = pinned(1, OUTSIDER, 330);
        let found = found(&run);
        assert_dropped(&run, &[(SHARE, Stage::Before)]);
        assert_eq!(
            (found.landing, found.share, found.next_share),
            (Landing::Inclusion, true, false),
            "{found:?}"
        );
        assert_registered_again(&run, found);
        assert_entered(&run, found, found.epoch.next());
    }

    /// The write that stores the share of the new output is held after it
    /// is applied, and the crash drops it: the share is in the secret store
    /// although the engine never saw it stored, never registered the next
    /// epoch, and never acknowledged the final block. The engine that comes
    /// back is in the inclusion window again with the new share already in
    /// its store. It applies the final block again, derives the same share,
    /// and enters the next epoch with it.
    ///
    /// The seed is the first of the same listing whose crash dropped that
    /// write, after it was applied, and no other, and did so again in the
    /// listings for `SURVEY_LATENCY=14` and `SURVEY_LATENCY=20`.
    #[test]
    fn crash_after_the_new_share_is_stored_is_survived() {
        let run = pinned(1, OUTSIDER, 1677);
        let found = found(&run);
        assert_dropped(&run, &[(SHARE, Stage::After)]);
        assert_eq!(
            (found.landing, found.share, found.next_share),
            (Landing::Inclusion, true, true),
            "{found:?}"
        );

        // The engine had not entered the next epoch when it was crashed.
        let next = found.epoch.next();
        let (before, _) = registered(&run, found);
        assert_eq!(registration(before, next), None, "{found:?}");
        assert_registered_again(&run, found);
        assert_entered(&run, found, next);
    }

    /// The engine has entered the third epoch and removes what it keeps of
    /// the first: the first epoch's entries from its journal, and the first
    /// epoch's secrets from its secret store. The write that removes the
    /// secrets is held before it is applied and the crash drops it, so the
    /// engine that comes back still holds the first epoch's secrets. It is
    /// at the boundary into the third epoch, and repeats it.
    ///
    /// The seed is the first of the seeds 0 to 2999 on which, in the
    /// listing of [`survey`] for `2:1:0..3000`, the crash dropped that
    /// write and no other at an engine that had entered the third epoch.
    #[test]
    fn crash_before_old_secrets_are_pruned_is_survived() {
        let run = pinned(2, OUTSIDER, 167);
        let found = found(&run);
        assert_dropped(&run, &[(PRUNE, Stage::Before)]);
        let (second, third) = (Epoch::new(1), Epoch::new(2));
        assert_eq!(
            (found.epoch, found.landing, found.oldest),
            (second, Landing::Boundary, Some(Epoch::zero())),
            "{found:?}"
        );
        assert_registered_again(&run, found);
        assert_entered(&run, found, third);
    }

    /// The write that removes the first epoch's secrets is held after it is
    /// applied, and the crash drops it: the secrets are gone although the
    /// engine never saw them removed. The engine that comes back holds
    /// nothing of the first epoch, repeats the boundary into the third, and
    /// needs none of it.
    ///
    /// The seed is the first of the same listing whose crash dropped that
    /// write, after it was applied, and no other at a share holder that had
    /// entered the third epoch.
    #[test]
    fn crash_after_old_secrets_are_pruned_is_survived() {
        let run = pinned(2, OUTSIDER, 2001);
        let found = found(&run);
        assert_dropped(&run, &[(PRUNE, Stage::After)]);
        let (second, third) = (Epoch::new(1), Epoch::new(2));
        assert_eq!(
            (found.epoch, found.landing, found.oldest),
            (second, Landing::Boundary, Some(second)),
            "{found:?}"
        );
        assert!(found.share && found.next_share, "{found:?}");
        assert_registered_again(&run, found);
        assert_entered(&run, found, third);
    }

    /// Slow, jittery, lossy links with a cut of every scope, under restarts.
    /// Nothing is required of such a run but that what it reached holds the
    /// invariants; these two reach a boundary.
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
                    cut(0, 2, 4, CutScope::Inbound),
                ],
            ),
        ] {
            let report = watched(input(2, ROTATE, 3, LOSSY, cuts, seed)).report;
            assert!(report.measured(), "{report}");
            assert_eq!(report.counts.correct_nodes, 5, "{report}");
            assert_eq!(report.counts.blocks, 0, "{report}");
            assert!(report.restarts.crashes > 0, "{report}");
        }
    }

    /// An input on whose first ceremony the reshare fails (see
    /// [`fixtures::failing`]).
    fn failing(epochs: u8) -> DkgReshareRestartsFuzzInput {
        let (links, cuts, seed) = fixtures::failing();
        let input = input(epochs, STAY, 1, links, cuts, seed);
        assert_eq!(schedule(&input), fixtures::failing_schedule());
        input
    }

    /// All five engines agree that the first ceremony failed and carry the
    /// first output into the second epoch, the restarted one included, and
    /// the shares they held stay valid under it (I1, I6). The second
    /// ceremony, with the cut healed and every engine up, reshares the
    /// carried output (I4, I5).
    #[test]
    fn failed_ceremony_carries_the_output_forward() {
        let report = watched(failing(2)).report;
        assert_eq!(report.outcome, Outcome::Completed, "{report}");
        assert_eq!(report.counts.correct_nodes, 5, "{report}");
        assert_eq!(report.counts.epochs, 2, "{report}");
        assert_eq!(report.counts.boundaries, 10, "{report}");
        assert_eq!(report.counts.failures, 1, "{report}");
        assert_eq!(report.counts.carried, 4, "{report}");
        assert_eq!(report.counts.successes, 1, "{report}");
        assert_eq!(report.counts.players, 4, "{report}");
        assert_eq!(report.counts.isolations, 48, "{report}");

        // Every member of the committee reached the second epoch, and holds
        // under it the share it carried: every epoch has four holders.
        assert_eq!(report.counts.kept, 4, "{report}");
        assert_eq!(report.counts.shares, 12, "{report}");
        assert_eq!(report.counts.reconstructions, 12, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
        assert_eq!(report.restarts.crashes, 1, "{report}");
        assert_eq!(report.restarts.dealing, 1, "{report}");
    }

    /// The link cut alone, with no crash in the ceremony's dealing window,
    /// does not fail the ceremony: each of the two dealers has one player
    /// unacknowledged, which a log may reveal.
    #[test]
    fn cut_link_alone_does_not_fail_the_ceremony() {
        let mut input = failing(1);
        input.raw_bytes = tape(0);
        assert_eq!(
            schedule(&input),
            vec![(2_400, Event::Crash(2)), (11_200, Event::Restart(2))]
        );
        let report = succeeded(input).report;
        assert!(report.elapsed < CUT_STEP * 64, "{report}");
    }

    /// The first run among [`SEEDS`], over the inputs `input` makes of
    /// them, that completes with every ceremony successful.
    fn first_completed(input: impl Fn(u16) -> DkgReshareRestartsFuzzInput + Sync) -> Run {
        first(SEEDS, input, |run| completed(run).then_some(())).0
    }

    #[test]
    fn roots_of_unity_runs() {
        let run = first_completed(|seed| {
            let mut input = input(2, ROTATE, 2, CLEAN, Vec::new(), seed);
            input.session.sharing_mode = Mode::RootsOfUnity;
            input
        });
        assert_succeeded(&run);
        assert_eq!(run.report.restarts.crashes, 2, "{}", run.report);
    }

    /// Any of the five identities may be outside the first committee.
    #[test]
    fn every_outsider_runs() {
        for outsider in 0..RESHARE_IDENTITIES as u8 {
            let run = first_completed(|seed| {
                let mut input = input(1, ROTATE, 1, CLEAN, Vec::new(), seed);
                input.session.outsider = outsider;
                input
            });
            assert_succeeded(&run);
        }
    }

    /// Inputs decoded the way libFuzzer's are, through the entry point it
    /// calls.
    #[test]
    fn decoded_inputs_run_through_the_entry_point() {
        for bytes in [&[][..], &[0x5a], &[0x01, 0x02, 0x03], &[0xff; 24]] {
            let input: DkgReshareRestartsFuzzInput = decode(bytes);
            fuzz_dkg_reshare_restarts(input.clone());
            let report = watched(input).report;
            assert_eq!(report.counts.correct_nodes, 5, "{report}");
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
        let run = || {
            let input = input(2, ROTATE, 3, links, cuts.clone(), 21);
            let (report, trace, _) = execute(input, |cluster| cluster);
            (report, trace)
        };
        let (report, trace) = run();
        assert_eq!((report, trace.clone()), run());
        let watched = watched(input(2, ROTATE, 3, links, cuts.clone(), 21));
        assert_eq!((watched.report, watched.trace), (report, trace));
    }

    /// What a partition holds decides how often the pacing holds its writes
    /// and how the report counts them, and is told by the partition's name.
    /// Every engine opens the reshare actor's journal, the state-sync plan,
    /// a Simplex journal, and the chain's partitions, and none the pacing
    /// does not know: a partition the DKG module names otherwise fails here.
    #[test]
    fn engines_open_the_partitions_the_pacing_knows() {
        let trace = watched(input(2, ROTATE, 1, CLEAN, Vec::new(), 21)).trace;
        for engine in 0..RESHARE_IDENTITIES as usize {
            assert_eq!(
                trace.opened(engine),
                vec![
                    Partition::Journal,
                    Partition::StateSync,
                    Partition::Consensus,
                    Partition::Chain,
                ],
                "engine {engine}"
            );
        }
    }

    /// Run `count` sampled inputs, decoded the way libFuzzer's are, and sum
    /// what they came to. Every run is checked as libFuzzer's are.
    fn sample(count: usize) -> Sample {
        Sample::of(sample::each(count, |bytes| {
            let (report, trace, _) = execute(decode(bytes), |cluster| cluster);
            Sampled {
                outcome: report.outcome,
                failed: report.counts.failures > 0,
                crashes: report.restarts.crashes,
                paced: report.paced,
                overlaps: trace.overlaps(),
            }
        }))
    }

    /// Whatever the input, no two identities are impaired at once.
    #[test]
    fn sampled_inputs_impair_one_identity_at_a_time() {
        let sample = sample(16);
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

    /// A fault a negative control plants at the boundary the oracle
    /// observes.
    #[derive(Clone, Copy)]
    enum Plant {
        /// Close the channels of the first identity's engine once it has
        /// been started the second number of times, so that the engine ends
        /// on its own.
        Sever(usize, usize),
        /// Panic in a task of this identity's engine.
        EnginePanic(usize),
        /// Panic in the harness, on its root task.
        HarnessPanic,
        /// Have this engine report a second description of the second
        /// epoch, with the other outcome.
        Describe(usize),
        /// Give the first identity the share the second holds of the second
        /// output.
        Swap(usize, usize),
        /// Give this identity a share of an output a trusted dealer dealt to
        /// the players of the second output.
        Forge(usize),
        /// Give this identity a share for an epoch no engine has reached.
        Stray(usize),
        /// Hand this identity's engine a secret store the oracle does not
        /// read, so that no share it stores is on record.
        Unrecorded(usize),
        /// Have this engine register, for the second epoch, the scheme it
        /// registered for the first.
        Stale(usize),
        /// Have this engine register a scheme for an epoch no engine has
        /// reached.
        Early(usize),
        /// Have this engine register the second epoch's scheme once more,
        /// without its share.
        Shareless(usize),
        /// Before the first identity's engine is started the second number
        /// of times, take from its secret store every secret of the epoch
        /// the engine resumes in and of the epochs before it, its share for
        /// that epoch among them. The record of the shares the store ever
        /// held keeps them.
        Lose(usize, usize),
        /// Before the first identity's engine is started the second number
        /// of times, hand it a copy of its secret store that the oracle does
        /// not read. No share the engine stores from then on is on record,
        /// so a share it carries into the next epoch is not.
        Unread(usize, usize),
        /// Give the engines another schedule than the oracle holds.
        Reschedule,
        /// Give the engines a first output with another transcript summary
        /// than the one the oracle holds, and the same sharing.
        Resummarize,
        /// Give the engines another deal of the first output than the oracle
        /// holds: its description, and each identity's share of it in a
        /// secret store the oracle does not read.
        Redeal,
        /// Have the first identity block the second.
        Block(usize, usize),
    }

    /// An epoch no engine of a run reaches.
    const UNREACHED: Epoch = Epoch::new(1_000);

    /// `output` with another transcript summary and everything else the same.
    fn resummarized(output: &Output<MockGroup, PublicKey>) -> Output<MockGroup, PublicKey> {
        let mut encoded = output.encode().to_vec();
        encoded[0] ^= 1;
        Output::read_cfg(
            &mut Copying(encoded.as_slice()),
            &(COMMITTEE, ModeVersion::v1()),
        )
        .expect("the output still decodes")
    }

    /// A secret store apart from `secrets` that holds what `secrets` holds
    /// for the epochs up to `last`: the shares, the dealer seeds, and the
    /// private dealings of the dealers among `participants`. Its writes are
    /// paced as those of `secrets` are.
    async fn copied(secrets: &Secrets, last: Epoch, participants: &[PublicKey]) -> Secrets {
        let mut held = secrets.clone();
        let mut copy = Secrets::default();
        for epoch in (0..=last.get()).map(Epoch::new) {
            if let Some(share) = held.get_share(epoch).await {
                copy.put_share(epoch, share).await;
            }
            if let Some(seed) = held.get_seed(epoch).await {
                copy.put_seed(epoch, seed).await;
            }
            for dealer in participants {
                if let Some(dealing) = held.get_dealing(epoch, dealer).await {
                    copy.put_dealing(epoch, dealer.clone(), dealing).await;
                }
            }
        }
        match secrets.pacing() {
            Some(pacing) => copy.paced(pacing),
            None => copy,
        }
    }

    /// The cluster of real engines with one fault planted.
    struct Planted {
        cluster: Cluster,
        plant: Plant,
        /// The starts of each identity's engine so far.
        starts: Vec<usize>,
        /// Whether the fault that is planted once the stack has settled has
        /// been planted.
        planted: bool,
    }

    impl Planted {
        /// Plant the fault among `cluster`'s engines. The oracle's view of
        /// the cluster has been taken, so what is replaced here is replaced
        /// for the engines only.
        fn new(mut cluster: Cluster, plant: Plant) -> Self {
            match plant {
                Plant::Unrecorded(engine) => {
                    let node = &mut cluster.nodes[engine];
                    node.secrets = Secrets::dealt(node.secrets.share(Epoch::zero()));
                }
                Plant::Reschedule => {
                    // The players of the third epoch's ceremony differ, and
                    // the second epoch's description names them.
                    let mut rotations = STAY;
                    rotations[2] = Rotation::Replace(0);
                    cluster.session.schedule = Schedule::new(
                        &cluster.session.participants,
                        usize::from(OUTSIDER),
                        &rotations,
                    );
                }
                Plant::Resummarize => {
                    let genesis = &mut cluster.session.genesis;
                    genesis.output = resummarized(&genesis.output);
                }
                Plant::Redeal => {
                    let committee = cluster.session.schedule.committee();
                    let (output, shares) = deal::<MockGroup, _, N3f1>(
                        TestRng::new(7),
                        Mode::NonZeroCounter,
                        committee,
                    )
                    .expect("a trusted deal must succeed");
                    cluster.session.genesis.output = output;
                    for (node, identity) in
                        cluster.nodes.iter_mut().zip(&*cluster.session.participants)
                    {
                        node.secrets = Secrets::dealt(shares.get_value(identity).cloned());
                    }
                }
                _ => {}
            }
            Self {
                starts: vec![0; cluster.nodes.len()],
                cluster,
                plant,
                planted: false,
            }
        }

        /// The description of the second epoch the engines hold.
        fn second(&self) -> Info {
            self.cluster.nodes[0]
                .records
                .deliveries()
                .into_iter()
                .find(|(epoch, _)| *epoch == Epoch::new(1))
                .expect("the engines have reached the second epoch")
                .1
        }
    }

    impl Stack for Planted {
        async fn start(&mut self, index: usize) -> Handle<()> {
            self.starts[index] += 1;
            if let Plant::Lose(victim, start) = self.plant
                && (victim, start) == (index, self.starts[index])
            {
                let node = &self.cluster.nodes[index];
                let (epoch, _) = node.crashed.expect("a restart follows a crash");
                let mut secrets = node.secrets.clone();
                secrets.prune(epoch.next()).await;
            }
            if let Plant::Unread(victim, start) = self.plant
                && (victim, start) == (index, self.starts[index])
            {
                let (epoch, _) = self.cluster.nodes[index]
                    .crashed
                    .expect("a restart follows a crash");
                let copy = copied(
                    &self.cluster.nodes[index].secrets,
                    epoch.next(),
                    &self.cluster.session.participants,
                )
                .await;
                self.cluster.nodes[index].secrets = copy;
            }
            let handle = self.cluster.start(index).await;
            match self.plant {
                Plant::Sever(victim, start) if (victim, start) == (index, self.starts[index]) => {
                    // Registering a channel again closes the receiver the
                    // engine holds.
                    let participant = &self.cluster.session.participants[index];
                    drop(reshare_stack::register(&self.cluster.oracle, participant).await);
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
            if std::mem::replace(&mut self.planted, true) {
                return;
            }
            let second = Epoch::new(1);
            let nodes = &self.cluster.nodes;
            let participants = &self.cluster.session.participants;
            match self.plant {
                Plant::Describe(engine) => {
                    let mut info = self.second();
                    info.outcome = EpochOutcome::Failure;
                    nodes[engine].records.delivered(second, info);
                }
                Plant::Swap(holder, other) => {
                    let share = nodes[other]
                        .secrets
                        .share(second)
                        .expect("the other identity holds a share of the second output");
                    nodes[holder].secrets.plant(second, share);
                }
                Plant::Forge(holder) => {
                    let players = self.second().output.players().clone();
                    let (_, shares) =
                        deal::<MockGroup, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, players)
                            .expect("a trusted deal must succeed");
                    let share = shares
                        .get_value(&participants[holder])
                        .expect("the identity is a player of the second output")
                        .clone();
                    nodes[holder].secrets.plant(second, share);
                }
                Plant::Stray(holder) => {
                    let share = nodes[holder]
                        .secrets
                        .share(second)
                        .expect("the identity holds a share of the second output");
                    nodes[holder].secrets.plant(UNREACHED, share);
                }
                Plant::Stale(engine) => {
                    let (_, first) = nodes[engine].records.registrations().remove(0);
                    nodes[engine].records.registered(second, first);
                }
                Plant::Early(engine) => {
                    let (_, first) = nodes[engine].records.registrations().remove(0);
                    nodes[engine].records.registered(UNREACHED, first);
                }
                Plant::Shareless(engine) => {
                    let info = self.second();
                    nodes[engine].records.registered(
                        second,
                        SchemeInfo::new(
                            &participants[engine],
                            info.output.players().clone(),
                            info.output.public().clone(),
                            None,
                        ),
                    );
                }
                Plant::Block(blocker, blocked) => {
                    let mut control = self.cluster.oracle.control(participants[blocker].clone());
                    block!(control, participants[blocked].clone(), "planted block");
                }
                _ => {}
            }
        }
    }

    /// Run, with `plant` planted, an input whose schedule crashes engine 3
    /// and brings it back within the first second and a half of the run. The
    /// only ceremony succeeds, and the stack settles once, when every
    /// engine has entered the second epoch.
    fn planted(plant: Plant) -> ReshareRestartsReport {
        let input = input(1, STAY, 1, CLEAN, Vec::new(), 21);
        assert_eq!(
            schedule(&input),
            vec![(600, Event::Crash(3)), (1_400, Event::Restart(3))]
        );
        execute(input, |cluster| Planted::new(cluster, plant)).0
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped before the run ended")]
    fn engine_that_stops_on_its_own_is_rejected() {
        planted(Plant::Sever(2, 1));
    }

    /// An engine a restart brought back is watched like the first one.
    #[test]
    #[should_panic(expected = "I8 violated: correct engines [3] stopped before the run ended")]
    fn restarted_engine_that_stops_on_its_own_is_rejected() {
        planted(Plant::Sever(3, 2));
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
    #[should_panic(
        expected = "I1 violated: engine 0 and engine 2 disagree on the description of \
                               epoch 1"
    )]
    fn description_that_differs_between_engines_is_rejected() {
        planted(Plant::Describe(2));
    }

    /// The records of an engine span its restarts, so an engine that
    /// reports another description after a restart contradicts itself.
    #[test]
    #[should_panic(
        expected = "I1 violated: engine 0 and engine 0 disagree on the description of \
                               epoch 1"
    )]
    fn description_that_changes_at_one_engine_is_rejected() {
        planted(Plant::Describe(0));
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 1 at index")]
    fn share_of_another_identity_is_rejected() {
        planted(Plant::Swap(1, 2));
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 2 holds for epoch 1 does not match")]
    fn share_of_another_output_is_rejected() {
        planted(Plant::Forge(2));
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 0 holds a share for epoch 1000, which no \
                               correct engine holds a description of"
    )]
    fn share_for_an_unreached_epoch_is_rejected() {
        planted(Plant::Stray(0));
    }

    /// The restarted engine completes the ceremony as a player of its
    /// output, and no share of that output is on its record.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 3 completed the successful reshare into \
                               epoch 1 as a player of its output and holds no share of it"
    )]
    fn player_without_a_share_is_rejected() {
        planted(Plant::Unrecorded(3));
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 registered a scheme for epoch 1 that does \
                               not carry the agreed public sharing"
    )]
    fn registration_of_another_sharing_is_rejected() {
        planted(Plant::Stale(1));
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 registered a scheme for epoch 1000, which \
                               no correct engine holds a description of"
    )]
    fn registration_for_an_unreached_epoch_is_rejected() {
        planted(Plant::Early(1));
    }

    /// An engine that holds a share for an epoch and registers the epoch
    /// without it, as one whose restart did not find its share would.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 3 registered the scheme of epoch 1 without \
                               the share it holds for it"
    )]
    fn registration_without_the_held_share_is_rejected() {
        planted(Plant::Shareless(3));
    }

    /// A restart that does not find the engine's share again (I2). The
    /// harness takes the share out of the secret store while the engine is
    /// down, which no fuzzed run does: a restart retains the store. The
    /// engine that comes back finds no share for the epoch it is in and
    /// registers the epoch's scheme without one, and the record of what its
    /// store ever held has the share.
    ///
    /// Where the share is lost decides which invariant reports it. An engine
    /// that comes back into an epoch it has voted in replays those votes
    /// under a scheme that cannot sign, consensus panics on them, and I8
    /// reports the panic before the registration is judged. So the share is
    /// lost at the last restart of the schedule, after a crash that found
    /// the engine past the last epoch the run was asked for with no vote of
    /// that epoch in its journal. The engine registers the scheme of the
    /// epoch it is in while it sets itself up, and goes on as a member that
    /// cannot sign while the run follows it to its next block.
    #[test]
    fn share_lost_across_a_restart_is_rejected() {
        let (run, found) = first_clean(1, 2, |run| {
            restarted_past_the_last_epoch(run)
                .filter(|found| found.votes == 0)
                .cloned()
        });

        // The restart is the engine's second start, or its third if the
        // schedule crashed it twice.
        let start = 1 + run
            .retained
            .iter()
            .filter(|restart| restart.engine == found.engine)
            .count();
        let rejected = std::panic::catch_unwind(|| {
            execute(run.input, |cluster| {
                Planted::new(cluster, Plant::Lose(found.engine, start))
            })
        });
        let message = *rejected
            .expect_err("the engine registers without the share on its record")
            .downcast::<String>()
            .expect("a check panics with a message");
        let expected = format!(
            "I2 violated: engine {} registered the scheme of epoch {} without the share it holds \
             for it",
            found.engine, found.epoch
        );
        assert!(message.starts_with(&expected), "{message}");
    }

    #[test]
    #[should_panic(expected = "I4 violated: the next players of epoch 1 are")]
    fn next_players_off_the_schedule_are_rejected() {
        planted(Plant::Reschedule);
    }

    /// The engines carry their first output through the failed ceremony,
    /// and it is not the output the oracle was given.
    #[test]
    #[should_panic(
        expected = "I6 violated: the failed ceremony did not carry the previous \
                               output into epoch 1 unchanged"
    )]
    fn failed_ceremony_that_changes_the_output_is_rejected() {
        execute(failing(1), |cluster| {
            Planted::new(cluster, Plant::Resummarize)
        });
    }

    /// The output the engines carry through the failed ceremony has another
    /// sharing than the shares on the oracle's record.
    #[test]
    #[should_panic(
        expected = "I6 violated: the share engine 0 held before the failed ceremony \
                               is not valid under the output carried into epoch 1"
    )]
    fn failed_ceremony_that_carries_another_sharing_is_rejected() {
        execute(failing(1), |cluster| Planted::new(cluster, Plant::Redeal));
    }

    /// The engine that was down for most of the failed ceremony carries its
    /// share into the second epoch and registers that epoch as a signer, and
    /// no share for the second epoch is on its record (I2). The harness hands
    /// the engine a copy of its store that the oracle does not read at its
    /// restart, which comes before the failed ceremony ends, so the record
    /// holds the share for the first epoch alone: what an engine that
    /// entered the second epoch without storing the carried share under it
    /// would leave. A share taken out of the engine's own store while it is
    /// down does not show this: the engine stores the carried share again at
    /// every start that finds it in the epoch.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 0 reached epoch 1 through a failed reshare as a \
                               player of the output carried into it and does not hold, under \
                               that epoch, the share it held of that output"
    )]
    fn carried_share_that_is_not_stored_under_the_new_epoch_is_rejected() {
        execute(failing(1), |cluster| {
            Planted::new(cluster, Plant::Unread(0, 2))
        });
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_is_rejected() {
        planted(Plant::Block(0, 3));
    }
}

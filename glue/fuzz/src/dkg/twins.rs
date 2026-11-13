//! The bootstrap Twins driver: five engines over four identities, no crashes.
//!
//! Three identities are correct and run one real bootstrap engine each. The
//! compromised identity runs two, sharing its key, each on its own storage
//! partitions and with its own secret store, so the two halves deal
//! differently under one identity. Its Simplex, marshal, and dissemination
//! channels are split per view by the selected twins scenario for the prefix
//! the input draws, the first views of the chain or every view, and its DKG
//! channel is split by the input's mask for the whole ceremony.
//!
//! The run ends when every correct engine has reported its completion or the
//! bounded timeout expires, and the invariants are checked over whatever was
//! reached.
//!
//! # A half may panic
//!
//! The two halves hold different secrets under one identity. A half can
//! therefore find, in a dealer log the ceremony selected, an ack its twin
//! signed for a dealing it never stored, or find the dealing it stored as its
//! own contradicted by its twin's. To the DKG module that is a node whose
//! secret store is corrupt, and the module stops such a node with a
//! deliberate panic. The runtime catches the panics of its tasks so that this
//! stops the half and nothing else. Every engine runs on its own
//! [`EngineContext`], so each panic of the run is recorded with the engine
//! that raised it and judged afterwards: a panic of a half is tolerated,
//! whatever it says, and a panic of a correct engine or of a harness task is
//! a violation of I8, as is a correct engine that stops.

use super::{
    BOOTSTRAP_RUN_TIMEOUT, COMMITTEE, DkgBootstrapFuzzInput, Outcome, PublicKey,
    context::EngineContext,
    identities,
    invariants::{self, Bootstrap, Bootstrapper, Counts, Ending},
    network::{Mask, Twins, halve},
    public_keys,
    runner::{self, Report},
    stack::{self, Completion, MAX_SUPPORTED_MODE},
    store::Secrets,
};
use crate::stateful::{
    network::TwinsScript,
    runner::{LINK, Panic, network_sized},
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::{group::Share, sharing::Mode};
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{NZUsize, channel::oneshot, ordered::Set, sync::Mutex};
use std::{fmt, sync::Arc};

/// Label the driver reports under.
const TARGET: &str = "glue-dkg-bootstrap";

/// The engine index of the compromised identity's secondary half.
const SECONDARY_ENGINE: usize = COMMITTEE.get() as usize;

/// What one bootstrap run observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootstrapReport {
    /// Why the run stopped.
    pub outcome: Outcome,
    /// How much each check compared.
    pub counts: Counts,
}

impl fmt::Display for BootstrapReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} correct_nodes={} completed={} successes={} agreements={} \
             shares={} reconstructions={} blocks={} tolerated_panics={}",
            self.outcome,
            self.counts.correct_nodes,
            self.counts.completed,
            self.counts.successes,
            self.counts.agreements,
            self.counts.shares,
            self.counts.reconstructions,
            self.counts.blocks,
            self.counts.tolerated_panics,
        )
    }
}

impl Report for BootstrapReport {
    fn measured(&self) -> bool {
        self.counts.completed > 0
    }
}

/// libFuzzer entry point.
pub fn fuzz_dkg_bootstrap(input: DkgBootstrapFuzzInput) {
    runner::fuzz(input.raw_bytes.clone(), input, run_dkg_bootstrap);
}

/// Run one bootstrap ceremony under one twins scenario and return what it
/// measured.
///
/// A run is fully determined by its input.
pub fn run_dkg_bootstrap(input: DkgBootstrapFuzzInput) -> BootstrapReport {
    execute(input, ()).0
}

/// Run `input` with `plant` planted, and return what the run measured with
/// every panic it raised, each of which was tolerated.
fn execute(input: DkgBootstrapFuzzInput, plant: impl Plant) -> (BootstrapReport, Vec<Panic>) {
    let entropy = input.raw_bytes.clone();
    let (observed, panics) = runner::execute(entropy.clone(), |context| {
        run(context, input, entropy, plant)
    });

    // Measurement point, outside the runtime so a violation is never caught.
    let Some(observed) = observed else {
        invariants::check_panics(&panics, &[]);
        let report = BootstrapReport {
            outcome: Outcome::NoCase,
            counts: Counts::default(),
        };
        return (report, panics);
    };
    let tolerated_panics = invariants::check_panics(&panics, &observed.halves);
    invariants::check_engines_running(&observed.stopped);
    let counts =
        invariants::check_bootstrap(&observed.bootstrap, &observed.committee, &observed.blocked);
    let report = BootstrapReport {
        outcome: observed.outcome,
        counts: Counts {
            tolerated_panics,
            ..counts
        },
    };
    (report, panics)
}

/// What a run observed, to be checked once the runtime has stopped.
struct Observations {
    outcome: Outcome,
    /// What every correct engine reported and its secret store held.
    bootstrap: Bootstrap,
    /// The identities the ceremony is among, in identity order.
    committee: Arc<[PublicKey]>,
    /// The engines of the compromised identity.
    halves: [usize; 2],
    blocked: Vec<(PublicKey, PublicKey)>,
    /// Correct engines that stopped before the run ended.
    stopped: Vec<usize>,
}

/// One engine's completion, recorded when the engine reports it, with the
/// share the engine's secret store held for epoch zero at that moment.
type Reported = Arc<Mutex<Option<(Ending, Option<Share>)>>>;

/// Record `completion` into `reported` once the engine sends it, with the
/// share `secrets` then holds.
fn await_completion(
    context: deterministic::Context,
    completion: oneshot::Receiver<Completion>,
    secrets: Secrets,
    reported: Reported,
) -> Handle<()> {
    context.spawn(move |_| async move {
        // An engine that stops without reporting leaves its record empty.
        let Ok(completion) = completion.await else {
            return std::future::pending().await;
        };
        let share = secrets.share(Epoch::zero());
        *reported.lock() = Some((stack::ending(completion), share));
    })
}

/// What the driver holds of a run once every engine has started, which is
/// what a [`Plant`] reaches.
struct Engines {
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    /// Every identity, in identity order.
    participants: Arc<[PublicKey]>,
    compromised: usize,
    /// One secret store per engine, held here so the oracle can read it.
    secrets: Vec<Secrets>,
    /// The correct engines, each with what it reported.
    correct: Vec<(usize, Reported)>,
}

impl Engines {
    /// What the run observed, ended for `outcome` with `stopped` the correct
    /// engines that stopped, where every engine runs in `mode`. Both halves
    /// of the compromised identity are excluded from the records.
    async fn observe(self, outcome: Outcome, stopped: Vec<usize>, mode: Mode) -> Observations {
        let blocked = runner::blocked(&self.oracle).await;
        let nodes = self
            .correct
            .iter()
            .map(|(engine, reported)| Bootstrapper {
                engine: *engine,
                identity: self.participants[*engine].clone(),
                completions: reported.lock().clone().into_iter().collect(),
                held: self.secrets[*engine].held_for(Epoch::zero()),
                share: self.secrets[*engine].share(Epoch::zero()),
            })
            .collect();
        Observations {
            outcome,
            bootstrap: Bootstrap { mode, nodes },
            committee: self.participants,
            halves: [self.compromised, SECONDARY_ENGINE],
            blocked,
            stopped,
        }
    }
}

/// A fault planted into a run at the boundary the oracle observes, in the
/// shape the reshare Twins driver uses. A bootstrap engine's configuration
/// has nothing a test needs to change, so there is no planting before the
/// engines start.
///
/// libFuzzer plants nothing. A test plants a fault to show that the oracle
/// the fuzz target runs rejects it.
trait Plant {
    /// Plant into the run once every engine has been started.
    async fn started(&mut self, _run: &Engines) {}

    /// Plant into what the engines left on record once the run has ended,
    /// before the oracle reads it.
    async fn ended(&mut self, _run: &Engines) {}
}

impl Plant for () {}

async fn run(
    context: deterministic::Context,
    input: DkgBootstrapFuzzInput,
    entropy: Vec<u8>,
    mut plant: impl Plant,
) -> Option<Observations> {
    let signers = identities();
    let participants: Arc<[PublicKey]> = public_keys(&signers);
    let committee = Set::from_iter_dedup(participants.iter().cloned());
    let oracle = network_sized(
        &context,
        &participants,
        LINK,
        NZUsize!(1),
        stack::max_message_size(),
    )
    .await;

    // Draw the twins script from the tape.
    let (compromised, script) = TwinsScript::select(
        entropy,
        participants.len(),
        input.prefix,
        input.sustained,
        input.case_selector,
    )?;

    // One secret store per engine, held here so the oracle can read it.
    let secrets: Vec<Secrets> = (0..=SECONDARY_ENGINE).map(|_| Secrets::default()).collect();
    let config = |engine: usize, identity: usize, partition: String| stack::Config {
        signer: signers[identity].clone(),
        participants: committee.clone(),
        partition,
        secrets: secrets[engine].clone(),
        sharing_mode: input.sharing_mode,
    };

    // Correct identities.
    let mut engines = Vec::with_capacity(participants.len() - 1);
    let mut correct = Vec::with_capacity(participants.len() - 1);
    let mut waiters = Vec::with_capacity(participants.len() - 1);
    for index in (0..participants.len()).filter(|index| *index != compromised) {
        let channels = stack::register(&oracle, &participants[index]).await;
        let node_context = context.child("correct").with_attribute("index", index);
        let (handle, completion) = stack::spawn(
            EngineContext::new(node_context.child("engine"), index),
            &oracle,
            config(index, index, format!("engine-{index}")),
            channels.votes,
            channels.certificates,
            channels.resolver,
            channels.backfill,
            channels.broadcast,
            channels.dkg,
        );
        let reported = Reported::default();
        waiters.push(await_completion(
            node_context.child("completion"),
            completion,
            secrets[index].clone(),
            reported.clone(),
        ));
        engines.push((index, handle));
        correct.push((index, reported));
    }

    // The compromised identity. Its view-addressable channels are split by
    // the scenario and its DKG channel by the mask.
    let raw = stack::register(&oracle, &participants[compromised]).await;
    let node_context = context
        .child("compromised")
        .with_attribute("index", compromised);
    let split = Twins::new(participants.clone(), script, MAX_SUPPORTED_MODE);
    let mask = Mask::new(&participants, compromised, input.mask);
    let child = |label| node_context.child(label);
    let (votes, votes_secondary) = halve(child("votes_split"), raw.votes, split.votes());
    let (certificates, certificates_secondary) = halve(
        child("certificates_split"),
        raw.certificates,
        split.certificates(),
    );
    let (resolver, resolver_secondary) =
        halve(child("resolver_split"), raw.resolver, split.resolver());
    let (backfill, backfill_secondary) =
        halve(child("backfill_split"), raw.backfill, split.backfill());
    let (broadcast, broadcast_secondary) =
        halve(child("broadcast_split"), raw.broadcast, split.broadcast());
    let (dkg, dkg_secondary) = halve(
        child("dkg_split"),
        raw.dkg,
        (mask.forwarder(), mask.router()),
    );

    // A half's handle is not watched: a half may stop.
    drop(stack::spawn(
        EngineContext::new(node_context.child("primary"), compromised),
        &oracle,
        config(
            compromised,
            compromised,
            format!("engine-{compromised}-primary"),
        ),
        votes,
        certificates,
        resolver,
        backfill,
        broadcast,
        dkg,
    ));
    drop(stack::spawn(
        EngineContext::new(node_context.child("secondary"), SECONDARY_ENGINE),
        &oracle,
        config(
            SECONDARY_ENGINE,
            compromised,
            format!("engine-{compromised}-secondary"),
        ),
        votes_secondary,
        certificates_secondary,
        resolver_secondary,
        backfill_secondary,
        broadcast_secondary,
        dkg_secondary,
    ));
    let started = Engines {
        context,
        oracle,
        participants,
        compromised,
        secrets,
        correct,
    };
    plant.started(&started).await;
    let (outcome, stopped) =
        runner::watch(&started.context, engines, waiters, BOOTSTRAP_RUN_TIMEOUT).await;
    plant.ended(&started).await;
    Some(started.observe(outcome, stopped, input.sharing_mode).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        DkgMask, Side,
        fixtures::{self, PREFIX, contradicted, decode, forged, tape},
    };
    use commonware_p2p::{Blocker as _, block};

    fn input(
        case_selector: u16,
        sustained: bool,
        mask: DkgMask,
        sharing_mode: Mode,
        seed: u8,
    ) -> DkgBootstrapFuzzInput {
        DkgBootstrapFuzzInput {
            case_selector,
            sustained,
            prefix: PREFIX,
            mask,
            sharing_mode,
            raw_bytes: tape(seed.into()),
        }
    }

    /// A mask under which the two halves' dealings reach different players.
    const SPLIT: DkgMask = DkgMask([Side::Primary, Side::Secondary, Side::Both]);

    #[test]
    fn whole_mask_runs() {
        for seed in 0..2 {
            let report = run_dkg_bootstrap(input(
                u16::from(seed),
                false,
                DkgMask::WHOLE,
                Mode::NonZeroCounter,
                seed,
            ));
            println!("{report}");
            assert_eq!(report.counts.correct_nodes, 3);
        }
    }

    #[test]
    fn split_mask_runs() {
        for seed in 0..2 {
            let report = run_dkg_bootstrap(input(
                7 + u16::from(seed),
                true,
                SPLIT,
                Mode::NonZeroCounter,
                seed,
            ));
            println!("{report}");
            assert_eq!(report.counts.correct_nodes, 3);
        }
    }

    /// The scenario may partition any number of leading views, or every
    /// view.
    #[test]
    fn every_length_of_prefix_runs() {
        for prefix in [Some(1), Some(9), Some(16), None] {
            for sustained in [false, true] {
                let report = run_dkg_bootstrap(DkgBootstrapFuzzInput {
                    prefix,
                    ..input(5, sustained, SPLIT, Mode::NonZeroCounter, 3)
                });
                println!("{prefix:?} sustained={sustained} {report}");
                assert_eq!(report.counts.correct_nodes, 3);
            }
        }
    }

    #[test]
    fn roots_of_unity_runs() {
        let report = run_dkg_bootstrap(input(3, false, SPLIT, Mode::RootsOfUnity, 5));
        println!("{report}");
        assert_eq!(report.counts.correct_nodes, 3);
    }

    /// A half that stops on the deliberate panic is tolerated and counted,
    /// and the entry point libFuzzer calls returns on such a run.
    #[test]
    fn stopped_half_is_tolerated() {
        let stopping = || input(7, true, SPLIT, Mode::NonZeroCounter, 0);
        let report = run_dkg_bootstrap(stopping());
        assert!(report.counts.tolerated_panics > 0);
        fuzz_dkg_bootstrap(stopping());
    }

    /// Inputs under whose masks one identity is dealt to by one half only
    /// and the other two by both, which is where a ceremony tends to select
    /// one half's dealing over the other's.
    fn lopsided() -> impl Iterator<Item = DkgBootstrapFuzzInput> {
        (0..96u8).map(|seed| {
            let mut sides = [Side::Both; 3];
            sides[usize::from(seed / 2) % 3] = if seed % 2 == 0 {
                Side::Primary
            } else {
                Side::Secondary
            };
            let mode = if seed % 3 == 0 {
                Mode::RootsOfUnity
            } else {
                Mode::NonZeroCounter
            };
            input(u16::from(seed), seed % 4 < 2, DkgMask(sides), mode, seed)
        })
    }

    /// The ceremony selects one half's dealing, so the other half stops on
    /// its own contradicted dealing: the panic is tolerated and counted.
    ///
    /// Whose dealing a ceremony selects depends on the timing of the
    /// engines, so the run is looked for among a range of inputs (see
    /// [`fixtures::first`]).
    #[test]
    fn half_with_a_contradicted_dealing_is_tolerated() {
        let (report, panics) = fixtures::first(lopsided(), 4, |input| {
            let (report, panics) = execute(input, ());
            contradicted(&panics).then_some((report, panics))
        });
        println!("{report}");
        assert!(panics.iter().all(|panic| panic.engine.is_some()));
        assert_eq!(report.counts.tolerated_panics, panics.len(), "{report}");
        assert_eq!(report.counts.correct_nodes, 3, "{report}");
    }

    /// Lists which inputs of the range a test looks for a contradicted
    /// dealing among show one.
    #[test]
    #[ignore = "a listing of the inputs that show a scenario"]
    fn survey_contradicted_dealings() {
        let inputs: Vec<_> = lopsided().collect();
        let shown =
            fixtures::sample::over(&inputs, |input| contradicted(&execute(input.clone(), ()).1));
        let shown: Vec<usize> = (0..inputs.len()).filter(|input| shown[*input]).collect();
        println!(
            "CONTRADICTED {} of {}: {shown:?}",
            shown.len(),
            inputs.len()
        );
    }

    #[test]
    fn replay_is_reproducible() {
        let run = || run_dkg_bootstrap(input(11, false, SPLIT, Mode::NonZeroCounter, 9));
        invariants::check_replay(run(), run());
    }

    /// Run the input `bytes` decode to, the way libFuzzer's are, through
    /// the entry point libFuzzer's runs take, and again with every report
    /// taken out of the records, where the shares are judged without the
    /// output.
    fn decoded(bytes: &[u8]) -> BootstrapReport {
        let input: DkgBootstrapFuzzInput = decode(bytes);
        let report = run_dkg_bootstrap(input.clone());
        execute(input, Planted(vec![Fault::Silence]));
        report
    }

    #[test]
    fn decoded_inputs_run_through_the_entry_point() {
        for bytes in [&[][..], &[0x5a], &[0x01, 0x02, 0x03], &[0xff; 24]] {
            let report = decoded(bytes);
            println!("{report}");
            assert_eq!(report.counts.correct_nodes, 3, "{report}");
        }
    }

    /// The same over a sample of decoded inputs.
    #[test]
    #[ignore = "runs 600 inputs twice"]
    fn large_sample_holds_invariants() {
        let reports = fixtures::sample::each(600, decoded);
        let completed = reports
            .iter()
            .filter(|report| report.outcome == Outcome::Completed)
            .count();
        let unreported = reports
            .iter()
            .filter(|report| report.counts.completed == 0)
            .count();
        println!(
            "SAMPLE runs={} completed={completed} unreported={unreported}",
            reports.len()
        );
    }

    /// A fault a negative control plants at the boundary the oracle
    /// observes.
    #[derive(Clone, Copy)]
    enum Fault {
        /// Close the channels of this identity's engine once it has started,
        /// so that the engine ends on its own.
        Sever(usize),
        /// Panic in a task of this engine.
        EnginePanic(usize),
        /// Panic in a task that belongs to no engine.
        TaskPanic,
        /// Panic in the harness, on its root task.
        HarnessPanic,
        /// Replace the report of this identity's engine with a failure.
        Disagree(usize),
        /// Replace the report of every correct engine with a failure.
        Fail,
        /// Take every correct engine's report out of the records, as a run
        /// that ends before any correct engine has reported leaves them.
        Silence,
        /// Give the first identity the share the second holds.
        Swap(usize, usize),
        /// Give this identity a share of an output a trusted dealer dealt.
        Forge(usize),
        /// Give this identity the share [`Fault::Forge`] gives it, and then
        /// its own share again, so that it holds its own share and once held
        /// the other.
        Overwrite(usize),
        /// Record the report of this identity's engine without the share the
        /// secret store held when the report was recorded.
        Unheld(usize),
        /// Have the first identity block the second.
        Block(usize, usize),
    }

    /// Faults planted together, in order.
    struct Planted(Vec<Fault>);

    impl Plant for Planted {
        async fn started(&mut self, engines: &Engines) {
            for fault in &self.0 {
                match *fault {
                    Fault::Sever(victim) => {
                        // Registering a channel again closes the receiver the
                        // engine holds.
                        let participant = &engines.participants[victim];
                        drop(stack::register(&engines.oracle, participant).await);
                    }
                    Fault::EnginePanic(engine) => {
                        let context = engines.context.child("planted");
                        drop(
                            EngineContext::new(context, engine)
                                .spawn(|_| async { panic!("planted") }),
                        );
                    }
                    Fault::TaskPanic => {
                        let context = engines.context.child("planted");
                        drop(context.spawn(|_| async { panic!("planted") }));
                    }
                    Fault::HarnessPanic => panic!("planted in the harness"),
                    _ => {}
                }
            }
        }

        async fn ended(&mut self, engines: &Engines) {
            let epoch = Epoch::zero();
            let reported = |engine: usize| {
                let (_, reported) = engines
                    .correct
                    .iter()
                    .find(|(correct, _)| *correct == engine)
                    .expect("the fault names a correct engine");
                reported
            };
            for fault in &self.0 {
                match *fault {
                    Fault::Disagree(engine) => {
                        if let Some((ending, _)) = &mut *reported(engine).lock() {
                            *ending = Ending::Failure;
                        }
                    }
                    Fault::Fail => {
                        for (_, reported) in &engines.correct {
                            if let Some((ending, _)) = &mut *reported.lock() {
                                *ending = Ending::Failure;
                            }
                        }
                    }
                    Fault::Silence => {
                        for (_, reported) in &engines.correct {
                            *reported.lock() = None;
                        }
                    }
                    Fault::Swap(holder, other) => {
                        if let Some(share) = engines.secrets[other].share(epoch) {
                            engines.secrets[holder].plant(epoch, share);
                        }
                    }
                    Fault::Forge(holder) => engines.secrets[holder].plant(epoch, forged(holder)),
                    Fault::Overwrite(holder) => {
                        let secrets = &engines.secrets[holder];
                        if let Some(share) = secrets.share(epoch) {
                            secrets.plant(epoch, forged(holder));
                            secrets.plant(epoch, share);
                        }
                    }
                    Fault::Unheld(engine) => {
                        if let Some((_, share)) = &mut *reported(engine).lock() {
                            *share = None;
                        }
                    }
                    Fault::Block(blocker, blocked) => {
                        let participants = &engines.participants;
                        let mut control = engines.oracle.control(participants[blocker].clone());
                        block!(control, participants[blocked].clone(), "planted block");
                    }
                    _ => {}
                }
            }
        }
    }

    /// The input the negative controls plant into: the identity the twins
    /// case compromises, its halves, and every correct engine complete the
    /// ceremony.
    fn planted_input() -> DkgBootstrapFuzzInput {
        input(0, false, DkgMask::WHOLE, Mode::NonZeroCounter, 0)
    }

    /// The identity the twins case of [`planted_input`] compromises.
    const COMPROMISED: usize = 3;

    /// Run [`planted_input`] with `faults` planted.
    fn planted(faults: &[Fault]) -> BootstrapReport {
        let (report, _) = execute(planted_input(), Planted(faults.to_vec()));
        println!("{report}");
        report
    }

    /// Without a fault, the ceremony of [`planted_input`] succeeds at the
    /// three correct engines and every check compares them, the I2 and I3
    /// checks without the output included once their reports are taken out.
    #[test]
    fn planted_input_is_judged_in_full() {
        let input = planted_input();
        let (compromised, _) = TwinsScript::select(
            input.raw_bytes.clone(),
            COMMITTEE.get() as usize,
            input.prefix,
            input.sustained,
            input.case_selector,
        )
        .expect("the input draws a twins case");
        assert_eq!(compromised, COMPROMISED);
        let report = planted(&[]);
        assert_eq!(report.outcome, Outcome::Completed);
        assert_eq!(
            report.counts,
            Counts {
                correct_nodes: 3,
                completed: 3,
                successes: 1,
                agreements: 2,
                shares: 3,
                reconstructions: 1,
                ..report.counts
            }
        );
        let report = planted(&[Fault::Silence]);
        assert_eq!(
            report.counts,
            Counts {
                correct_nodes: 3,
                completed: 0,
                successes: 0,
                agreements: 0,
                shares: 3,
                reconstructions: 1,
                ..report.counts
            }
        );
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped before the run ended")]
    fn engine_that_stops_on_its_own_is_rejected() {
        planted(&[Fault::Sever(2)]);
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engine 1 panicked")]
    fn correct_engine_panic_is_rejected() {
        planted(&[Fault::EnginePanic(1)]);
    }

    /// The same panic in a task of a half is tolerated.
    #[test]
    fn half_panic_is_tolerated() {
        let report = planted(&[Fault::EnginePanic(SECONDARY_ENGINE)]);
        assert!(report.counts.tolerated_panics > 0, "{report}");
    }

    #[test]
    #[should_panic(expected = "I8 violated: a task of no engine panicked")]
    fn task_of_no_engine_panic_is_rejected() {
        planted(&[Fault::TaskPanic]);
    }

    #[test]
    #[should_panic(expected = "I8 violated: the run's root task panicked")]
    fn harness_panic_is_rejected() {
        planted(&[Fault::HarnessPanic]);
    }

    #[test]
    #[should_panic(expected = "I1 violated: engines 0 and 2 disagree on the ceremony of epoch 0")]
    fn report_that_differs_between_engines_is_rejected() {
        planted(&[Fault::Disagree(2)]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 0 at index \
                               Participant(2), but its identity is at Some(Participant(1)) in \
                               the output's players")]
    fn share_of_another_identity_is_rejected() {
        planted(&[Fault::Swap(1, 2)]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 2 holds for epoch 0 does not match")]
    fn share_of_another_output_is_rejected() {
        planted(&[Fault::Forge(2)]);
    }

    /// The share of the other output is overwritten with the engine's own
    /// before the run's records are read, so only the record of every share
    /// the secret store held shows it.
    #[test]
    #[should_panic(expected = "I2 violated: the share engine 0 holds for epoch 0 does not match")]
    fn share_of_another_output_overwritten_before_the_end_is_rejected() {
        planted(&[Fault::Overwrite(0)]);
    }

    /// Engine 2 holds its share at the end of the run, and is judged at its
    /// report by what it held then.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 2 completed the successful ceremony of epoch 0 \
                               without a share"
    )]
    fn report_recorded_without_a_share_is_rejected() {
        planted(&[Fault::Unheld(2)]);
    }

    /// With no report on record the shares are judged without the output.
    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 0 at index \
                               Participant(2), but its identity is at Some(Participant(1)) in \
                               the committee")]
    fn share_of_another_identity_with_no_report_on_record_is_rejected() {
        planted(&[Fault::Silence, Fault::Swap(1, 2)]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 0 held two different shares of epoch 0")]
    fn second_share_with_no_report_on_record_is_rejected() {
        planted(&[Fault::Silence, Fault::Forge(0)]);
    }

    // I3 has no control through this target. With the agreed output, I2
    // leaves each correct engine only the one share the output accepts, and
    // any quorum of those reconstructs the output's key. Without it, the
    // three correct engines hold no more than one quorum of shares, and any
    // three shares lie on a polynomial of the degree the output has, so
    // there is nothing to compare them with (see
    // `unreported_shares_of_one_quorum_are_not_compared` in the invariants).
    // The restart target's four engines give I3 a control without a report.

    #[test]
    #[should_panic(
        expected = "I6 violated: engine 0 holds a share of epoch 0 although the ceremony failed"
    )]
    fn share_after_a_failed_ceremony_is_rejected() {
        planted(&[Fault::Fail]);
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_is_rejected() {
        planted(&[Fault::Block(0, 2)]);
    }
}

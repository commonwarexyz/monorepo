//! The reshare Twins driver: six engines over five identities, no crashes.
//!
//! The run starts from an output a trusted dealer deals to the first
//! committee, four of the five identities, and reshares it for the number of
//! epochs the input selects. Before each ceremony the committee either stays
//! or takes the outside identity in for one of its members, as the input
//! schedules.
//!
//! Four identities are correct and run one real reshare engine each. The
//! compromised identity runs two, sharing its key, each on its own storage
//! partitions and with its own secret store; both stores start with the
//! identity's share of the first output. The input picks the identity
//! outside the first committee among the other four, so the compromised
//! identity is always in the first committee and deals in its ceremony. Its
//! Simplex, marshal, and dissemination channels are split per view by the
//! selected twins scenario for the prefix the input draws, the first views of
//! every epoch or every view, its DKG channel is split by the input's mask
//! for each epoch's ceremony, and its secondary half runs the faulty
//! application. The scenario's scripted leaders lead the views they are
//! scripted for in every epoch whose committee holds them.
//!
//! The run ends when every correct engine has processed the last boundary
//! block of the selected epochs, when a correct engine stops, or when the
//! bounded timeout expires, and the invariants are checked over every
//! boundary that was reached and every finalized block a correct engine was
//! delivered.
//!
//! A half of the compromised identity may panic, as in the bootstrap driver
//! (see [`super::twins`]): each engine runs on its own [`EngineContext`], a
//! panic of a half is tolerated, and a panic of a correct engine or of a
//! harness task is a violation of I8, as is a correct engine that stops.

use super::{
    DkgReshareFuzzInput, EPOCH_LENGTH, Outcome, PublicKey, RESHARE_IDENTITIES, RESHARE_RUN_TIMEOUT,
    SessionControls, TRACKED_PEER_SETS,
    app::App,
    context::EngineContext,
    faulty::{Faulty, Plan, spare_log},
    invariants::{self, Records, Reshare, ReshareCounts, Resharer},
    joiner::Entry,
    network::halve,
    public_keys,
    reshare_cluster::Session,
    reshare_input::PEERS,
    reshare_network::{Masks, Scripted, Simplex, Twins},
    reshare_stack::{self, Config},
    runner::{self, Report},
    signers,
    store::Secrets,
};
use crate::stateful::{
    network::{TwinsScript, shared_router},
    runner::{LINK, Panic, network_sized},
};
use commonware_consensus::types::Epoch;
use commonware_p2p::simulated::Oracle;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::FuzzRng;
use std::{
    fmt,
    sync::{Arc, atomic::Ordering},
};

/// Label the driver reports under.
const TARGET: &str = "glue-dkg-reshare";

/// The engine index of the compromised identity's secondary half.
const SECONDARY_ENGINE: usize = RESHARE_IDENTITIES as usize;

/// What one reshare run observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReshareReport {
    /// Why the run stopped.
    pub outcome: Outcome,
    /// Epochs the run was asked to complete.
    pub asked: u8,
    /// Proposals in which the faulty application replaced the payload the
    /// reshare wrapper selected.
    pub deviations: usize,
    /// How much each check compared.
    pub counts: ReshareCounts,
    /// Registrations of an epoch the engine holds a share for, each required
    /// to carry that share under I2.
    pub signers: usize,
}

impl fmt::Display for ReshareReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} asked={} epochs={} correct_nodes={} boundaries={} successes={} \
             failures={} agreements={} registrations={} signers={} shares={} players={} \
             reconstructions={} continuities={} isolations={} carried={} blocks={} \
             placements={} dealer_logs={} epoch_infos={} deviations={} tolerated_panics={}",
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
            self.counts.blocks,
            self.counts.placements,
            self.counts.dealer_logs,
            self.counts.epoch_infos,
            self.deviations,
            self.counts.tolerated_panics,
        )
    }
}

impl Report for ReshareReport {
    fn measured(&self) -> bool {
        self.counts.boundaries > 0
    }
}

/// libFuzzer entry point.
pub fn fuzz_dkg_reshare(input: DkgReshareFuzzInput) {
    runner::fuzz(input.raw_bytes.clone(), input, run_dkg_reshare);
}

/// Run the selected epochs of resharing under one twins scenario and return
/// what the run measured.
///
/// A run is fully determined by its input.
pub fn run_dkg_reshare(input: DkgReshareFuzzInput) -> ReshareReport {
    execute(input, ()).0
}

/// What a plant reaches of a run: the engines' surroundings, and the records
/// and secret stores the oracle reads.
struct Planting<'a> {
    context: &'a deterministic::Context,
    oracle: &'a Oracle<PublicKey, deterministic::Context>,
    /// The identities, in identity order.
    participants: &'a [PublicKey],
    /// The engines of the correct identities, each at its identity's index.
    correct: &'a [usize],
    /// One record and one secret store per engine.
    records: &'a [Records],
    secrets: &'a [Secrets],
}

/// A fault planted into a run at the boundary the oracle observes.
///
/// libFuzzer plants nothing. A test plants a fault to show that the oracle
/// the fuzz target runs rejects it.
trait Plant {
    /// Change the session the engines are configured with. The oracle holds
    /// the session as it was dealt.
    fn configure(&mut self, _session: &mut Session) {}

    /// Plant into the run once every engine has been started.
    async fn started(&mut self, _run: &Planting<'_>) {}

    /// Plant into what the engines left on record once the run has ended,
    /// before the oracle reads it.
    async fn ended(&mut self, _run: &Planting<'_>) {}
}

impl Plant for () {}

/// Run `input` with `plant` planted, and return what the run measured with
/// every panic it raised, each of which was tolerated.
fn execute(input: DkgReshareFuzzInput, plant: impl Plant) -> (ReshareReport, Vec<Panic>) {
    let entropy = input.raw_bytes.clone();
    let asked = input.epochs;
    let (observed, panics) = runner::execute(entropy.clone(), |context| {
        run(context, input, entropy, plant)
    });

    // Measurement point, outside the runtime so a violation is never caught.
    let Some(observed) = observed else {
        invariants::check_panics(&panics, &[]);
        let report = ReshareReport {
            outcome: Outcome::NoCase,
            asked,
            deviations: 0,
            counts: ReshareCounts::default(),
            signers: 0,
        };
        return (report, panics);
    };
    let tolerated_panics = invariants::check_panics(&panics, &observed.halves);
    invariants::check_engines_running(&observed.stopped);
    let counts = invariants::check_reshare(&observed.reshare, &observed.blocked);
    let signers = invariants::check_registered_shares(&observed.reshare);
    let report = ReshareReport {
        outcome: observed.outcome,
        asked,
        deviations: observed.deviations,
        counts: ReshareCounts {
            tolerated_panics,
            ..counts
        },
        signers,
    };
    (report, panics)
}

/// What a run observed, to be checked once the runtime has stopped.
struct Observations {
    outcome: Outcome,
    reshare: Reshare,
    /// The engines of the compromised identity.
    halves: [usize; 2],
    blocked: Vec<(PublicKey, PublicKey)>,
    /// Correct engines that stopped before the run ended.
    stopped: Vec<usize>,
    /// Proposals in which the faulty application deviated.
    deviations: usize,
}

/// Complete once the engine behind `records` has registered the scheme of
/// `epoch`, which it does when it has processed the block that introduces the
/// epoch.
fn await_epoch(context: deterministic::Context, records: &Records, epoch: Epoch) -> Handle<()> {
    let mut registered = records.watch();
    context.spawn(move |_| async move {
        loop {
            match registered.recv().await {
                Some(reached) if reached >= epoch => return,
                Some(_) => {}
                None => return std::future::pending().await,
            }
        }
    })
}

/// The identity outside the first committee: the one at position `selected`
/// among the identities other than `compromised`, in identity order. The
/// compromised identity is therefore in the first committee, and both of its
/// halves start with its share of the first output.
fn outsider(compromised: usize, selected: u8) -> u8 {
    let position = usize::from(selected) % PEERS;
    let outsider = if position < compromised {
        position
    } else {
        position + 1
    };
    u8::try_from(outsider).expect("an identity's index fits in a byte")
}

async fn run(
    mut context: deterministic::Context,
    input: DkgReshareFuzzInput,
    entropy: Vec<u8>,
    mut plant: impl Plant,
) -> Option<Observations> {
    let signers = signers(RESHARE_IDENTITIES);
    let participants: Arc<[PublicKey]> = public_keys(&signers);
    let oracle = network_sized(
        &context,
        &participants,
        LINK,
        TRACKED_PEER_SETS,
        reshare_stack::max_message_size(),
    )
    .await;

    // Draw the twins script from the tape.
    let (compromised, script) = TwinsScript::select(
        entropy.clone(),
        participants.len(),
        input.prefix,
        input.sustained,
        input.case_selector,
    )?;

    // The first output comes from a trusted deal among the first committee,
    // which holds the compromised identity.
    let controls = SessionControls {
        epochs: input.epochs,
        sharing_mode: input.sharing_mode,
        outsider: outsider(compromised, input.outsider),
        rotations: input.rotations,
        mailbox: input.mailbox,
    };
    let dealt = Session::deal(&mut context, signers, &controls);
    let mut session = dealt.clone();
    plant.configure(&mut session);

    // One secret store and one set of records per engine, held here so the
    // oracle can read them. Both halves of the compromised identity start
    // with its share of the first output, each in its own store.
    let identity_of = |engine: usize| {
        if engine == SECONDARY_ENGINE {
            compromised
        } else {
            engine
        }
    };
    let secrets: Vec<Secrets> = (0..=SECONDARY_ENGINE)
        .map(|engine| Secrets::dealt(session.share(identity_of(engine))))
        .collect();
    let records: Vec<Records> = (0..=SECONDARY_ENGINE).map(|_| Records::default()).collect();
    let elector = Scripted::new(&script, &participants);
    let config = |engine: usize, partition: String| Config {
        signer: session.signers[identity_of(engine)].clone(),
        partition,
        secrets: secrets[engine].clone(),
        sharing_mode: session.sharing_mode,
        genesis: session.genesis.clone(),
        schedule: session.schedule.clone(),
        records: records[engine].clone(),
        application: App,
        elector: elector.clone(),
        entry: Entry::Genesis,
        mailbox: session.mailbox,
    };

    // Correct identities. Each is done once it has registered the scheme of
    // the epoch after the last one the run was asked to complete.
    let correct: Vec<usize> = (0..participants.len())
        .filter(|index| *index != compromised)
        .collect();
    let mut engines = Vec::with_capacity(correct.len());
    let mut waiters = Vec::with_capacity(correct.len());
    for &index in &correct {
        let channels = reshare_stack::register(&oracle, &participants[index]).await;
        let node_context = context.child("correct").with_attribute("index", index);
        waiters.push(await_epoch(
            node_context.child("completion"),
            &records[index],
            session.last,
        ));
        let handle = reshare_stack::spawn(
            EngineContext::new(node_context.child("engine"), index),
            &oracle,
            config(index, format!("engine-{index}")),
            channels.chain.votes,
            channels.chain.certificates,
            channels.chain.resolver,
            channels.chain.backfill,
            channels.chain.broadcast,
            channels.chain.dkg,
            channels.probe,
        );
        engines.push((index, handle));
    }

    // The compromised identity. Its view-addressable channels are split by
    // the scenario, its DKG channel by the epoch's mask, and its probe
    // channel is shared by both halves.
    let raw = reshare_stack::register(&oracle, &participants[compromised]).await;
    let node_context = context
        .child("compromised")
        .with_attribute("index", compromised);
    let split = Twins::new(participants.clone(), script);
    let masks = Masks::new(&participants, compromised, &input.masks);
    let child = |label| node_context.child(label);
    let (votes, votes_secondary) = halve(
        child("votes_split"),
        raw.chain.votes,
        split.simplex(Simplex::Votes),
    );
    let (certificates, certificates_secondary) = halve(
        child("certificates_split"),
        raw.chain.certificates,
        split.simplex(Simplex::Certificates),
    );
    let (resolver, resolver_secondary) = halve(
        child("resolver_split"),
        raw.chain.resolver,
        split.simplex(Simplex::Resolver),
    );
    let (backfill, backfill_secondary) = halve(
        child("backfill_split"),
        raw.chain.backfill,
        split.backfill(),
    );
    let (broadcast, broadcast_secondary) = halve(
        child("broadcast_split"),
        raw.chain.broadcast,
        split.broadcast(),
    );
    let (dkg, dkg_secondary) = halve(
        child("dkg_split"),
        raw.chain.dkg,
        (masks.forwarder(), masks.router()),
    );
    let (probe_rx, probe_rx_secondary) = raw
        .probe
        .1
        .split_with(child("probe_split"), shared_router());

    // A half's handle is not watched: a half may stop.
    drop(reshare_stack::spawn(
        EngineContext::new(node_context.child("primary"), compromised),
        &oracle,
        config(compromised, format!("engine-{compromised}-primary")),
        votes,
        certificates,
        resolver,
        backfill,
        broadcast,
        dkg,
        (raw.probe.0.clone(), probe_rx),
    ));

    // The secondary half runs the faulty application, whose plan and spare
    // dealer log come from the tape.
    let mut fault_rng = FuzzRng::new(entropy);
    let plan = Plan::new(&mut fault_rng);
    let spare = spare_log(
        &mut fault_rng,
        &session.genesis,
        &session.signers[compromised],
        session.share(compromised),
        session.sharing_mode,
    );
    let faulty = Faulty::new(
        plan,
        participants[compromised].clone(),
        session.genesis.clone(),
        spare,
        EPOCH_LENGTH,
        session.sharing_mode,
    );
    let deviations = faulty.deviations();
    let secondary = config(SECONDARY_ENGINE, format!("engine-{compromised}-secondary"));
    drop(reshare_stack::spawn(
        EngineContext::new(node_context.child("secondary"), SECONDARY_ENGINE),
        &oracle,
        Config {
            signer: secondary.signer,
            partition: secondary.partition,
            secrets: secondary.secrets,
            sharing_mode: secondary.sharing_mode,
            genesis: secondary.genesis,
            schedule: secondary.schedule,
            records: secondary.records,
            application: faulty,
            elector: secondary.elector,
            entry: secondary.entry,
            mailbox: secondary.mailbox,
        },
        votes_secondary,
        certificates_secondary,
        resolver_secondary,
        backfill_secondary,
        broadcast_secondary,
        dkg_secondary,
        (raw.probe.0, probe_rx_secondary),
    ));
    let run = Planting {
        context: &context,
        oracle: &oracle,
        participants: &participants,
        correct: &correct,
        records: &records,
        secrets: &secrets,
    };
    plant.started(&run).await;
    let (outcome, stopped) =
        runner::watch(run.context, engines, waiters, RESHARE_RUN_TIMEOUT).await;
    plant.ended(&run).await;

    // Both halves of the compromised identity are excluded from the records.
    let blocked = runner::blocked(run.oracle).await;
    let nodes = run
        .correct
        .iter()
        .map(|&engine| {
            Resharer::observed(
                engine,
                run.participants[engine].clone(),
                &run.records[engine],
                run.secrets[engine].held(),
            )
        })
        .collect();
    Some(Observations {
        outcome,
        reshare: Reshare {
            genesis: dealt.genesis,
            schedule: dealt.schedule,
            nodes,
        },
        halves: [compromised, SECONDARY_ENGINE],
        blocked,
        stopped,
        deviations: deviations.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        DkgMask, Info, MAX_EPOCHS, MockGroup, Rotation, Side,
        fixtures::{self, PREFIX, ROTATE, STAY, contradicted, decode, resummarized, tape},
        reshare_input::ROTATIONS,
        reshare_restarts_input::ROOMY_MAILBOX,
        schedule::Schedule,
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::bls12381::{
        dkg::feldman_desmedt::deal, primitives::sharing::Mode,
    };
    use commonware_glue::dkg::types::{EpochOutcome, Payload, SchemeInfo};
    use commonware_p2p::{Blocker as _, block};
    use commonware_utils::{N3f1, TestRng};
    use std::collections::BTreeSet;

    /// The masks under which both halves exchange ceremony messages with
    /// every identity in every epoch.
    const WHOLE: [DkgMask<4>; MAX_EPOCHS as usize] = [DkgMask::WHOLE; MAX_EPOCHS as usize];

    /// Masks under which the two halves' dealings reach different players.
    const SPLIT: [DkgMask<4>; MAX_EPOCHS as usize] = [
        DkgMask([Side::Primary, Side::Secondary, Side::Both, Side::Primary]),
        DkgMask([Side::Secondary, Side::Both, Side::Primary, Side::Secondary]),
        DkgMask([Side::Both, Side::Primary, Side::Secondary, Side::Both]),
    ];

    fn input(
        case_selector: u16,
        epochs: u8,
        masks: [DkgMask<4>; MAX_EPOCHS as usize],
        rotations: [Rotation; ROTATIONS],
        seed: u8,
    ) -> DkgReshareFuzzInput {
        DkgReshareFuzzInput {
            case_selector,
            sustained: case_selector % 2 == 1,
            prefix: PREFIX,
            epochs,
            masks,
            sharing_mode: if seed.is_multiple_of(2) {
                Mode::NonZeroCounter
            } else {
                Mode::RootsOfUnity
            },
            outsider: seed % PEERS as u8,
            rotations,
            mailbox: ROOMY_MAILBOX,
            raw_bytes: tape(seed.into()),
        }
    }

    /// Runs one fixed input and asserts that the run fed every check a
    /// successful reshare exercises: what the engines registered, the shares
    /// they stored, the sets built from those shares, and the finalized
    /// blocks the engines were delivered.
    fn measured(input: DkgReshareFuzzInput) -> ReshareReport {
        let report = run_dkg_reshare(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run measured nothing and must not be counted as passing: {report}"
        );
        let counts = &report.counts;
        assert_eq!(counts.correct_nodes, 4);
        assert!(counts.successes > 0, "no ceremony succeeded: {report}");
        assert!(
            counts.registrations > 0,
            "no registration was checked: {report}"
        );

        // Every correct member of the first committee registers the first
        // epoch with its share, and so does every correct player of each
        // output after it.
        assert!(
            report.signers >= 3,
            "no registered share was checked: {report}"
        );
        assert!(counts.shares > 0, "no share was checked: {report}");
        assert!(
            counts.players > 0,
            "no player was required a share: {report}"
        );
        assert!(
            counts.reconstructions > 0,
            "no share set reconstructed: {report}"
        );
        assert!(
            counts.isolations > 0,
            "no mixed share set was checked: {report}"
        );

        // An engine that was delivered the description of an epoch was
        // delivered every block of the epoch before it, the quorum of dealer
        // logs behind the successful ceremony among them.
        assert!(
            counts.placements >= counts.boundaries * (EPOCH_LENGTH.get() as usize - 1),
            "blocks were delivered whose placement was not checked: {report}"
        );
        assert!(
            counts.dealer_logs > 0,
            "no dealer log's placement was checked: {report}"
        );
        assert_eq!(
            counts.epoch_infos, counts.boundaries,
            "an epoch description was delivered and its placement not checked: {report}"
        );
        report
    }

    #[test]
    fn one_epoch_over_a_fixed_committee_holds_invariants() {
        let report = measured(input(0, 1, WHOLE, STAY, 0));
        assert!(report.counts.epochs >= 1);
        assert!(report.counts.continuities >= 1);
    }

    #[test]
    fn three_epochs_over_a_fixed_committee_hold_invariants() {
        let report = measured(input(2, 3, WHOLE, STAY, 2));
        assert!(report.counts.epochs >= 3);
    }

    #[test]
    fn rotating_committee_holds_invariants() {
        let report = measured(input(4, 3, WHOLE, ROTATE, 1));
        assert!(report.counts.epochs >= 3);
    }

    #[test]
    fn split_masks_hold_invariants() {
        for seed in 0..3 {
            measured(input(7 + u16::from(seed), 2, SPLIT, ROTATE, seed));
        }
    }

    /// The scenario may partition any number of leading views of every
    /// epoch, or every view.
    #[test]
    fn every_length_of_prefix_runs() {
        for (prefix, case_selector) in [(Some(1), 0), (Some(16), 2), (None, 0), (None, 1)] {
            let report = run_dkg_reshare(DkgReshareFuzzInput {
                prefix,
                ..input(case_selector, 1, SPLIT, ROTATE, 1)
            });
            println!("{prefix:?} case {case_selector}: {report}");
            assert_eq!(report.counts.correct_nodes, 4);
        }
    }

    /// The target explores a scenario per case selector; every one of them is
    /// a regression case.
    #[test]
    fn selected_cases_hold_invariants() {
        for case_selector in 0..6u16 {
            let seed = u8::try_from(case_selector).expect("fits");
            let report = run_dkg_reshare(input(
                case_selector,
                seed % MAX_EPOCHS + 1,
                if case_selector % 2 == 0 { SPLIT } else { WHOLE },
                if case_selector % 3 == 0 { STAY } else { ROTATE },
                seed.wrapping_mul(7),
            ));
            println!("case {case_selector}: {report}");
            assert_eq!(report.counts.correct_nodes, 4);
            assert!(report.counts.shares > 0, "no share was checked: {report}");
        }
    }

    /// The entry point libFuzzer calls returns on a run in which a half of
    /// the compromised identity stops.
    #[test]
    fn entry_point_returns() {
        fuzz_dkg_reshare(input(7, 1, SPLIT, STAY, 0));
    }

    /// The secondary half proposes payloads other than the selected ones, and
    /// the correct engines still agree on every boundary.
    #[test]
    fn faulty_proposals_hold_invariants() {
        let deviations: usize = (0..4)
            .map(|seed| measured(input(u16::from(seed), 3, WHOLE, STAY, seed)).deviations)
            .sum();
        assert!(deviations > 0);
    }

    /// Inputs of one epoch under whose mask one identity is dealt to by one
    /// half only and the others by both, which is where a ceremony tends to
    /// select one half's dealing over the other's.
    fn lopsided() -> impl Iterator<Item = DkgReshareFuzzInput> {
        (0..96u8).map(|seed| {
            let mut sides = [Side::Both; 4];
            sides[usize::from(seed / 2) % 4] = if seed % 2 == 0 {
                Side::Primary
            } else {
                Side::Secondary
            };
            let masks = [DkgMask(sides), DkgMask::WHOLE, DkgMask::WHOLE];
            input(u16::from(seed), 1, masks, STAY, seed)
        })
    }

    /// A half finds the dealing it stored contradicted by its twin's and
    /// stops: the panic is tolerated and counted.
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
        assert_eq!(report.counts.correct_nodes, 4, "{report}");
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

    /// Inputs as libFuzzer first produces them decode to whole sessions that
    /// hold the invariants. A ceremony may fail under a long prefix, which
    /// can script the leaders of a whole epoch, so a run is held to having
    /// ended a ceremony either way.
    #[test]
    fn short_inputs_hold_invariants() {
        for byte in [0x00u8, 0x5a, 0xa9, 0xff] {
            let input: DkgReshareFuzzInput = decode(&[byte]);
            let prefix = input.prefix;
            let report = run_dkg_reshare(input);
            println!("{prefix:?}: {report}");
            assert_eq!(report.counts.correct_nodes, 4);
            assert!(
                report.counts.successes + report.counts.failures > 0,
                "no ceremony ended: {report}"
            );
        }
    }

    /// Decoded inputs, run through the target's entry point, hold the
    /// invariants.
    #[test]
    #[ignore = "runs 600 inputs"]
    fn large_sample_holds_invariants() {
        let count = std::env::var("SAMPLE").map_or(600, |count| {
            count.parse().expect("SAMPLE is a number of inputs")
        });
        let reports = fixtures::sample::each(count, |bytes| {
            let input: DkgReshareFuzzInput = decode(bytes);
            run_dkg_reshare(input)
        });
        let count = |holds: &dyn Fn(&ReshareReport) -> bool| {
            reports.iter().filter(|report| holds(report)).count()
        };
        println!(
            "runs={} completed={} failed={} signers={} deviations={} tolerated_panics={}",
            reports.len(),
            count(&|report| report.outcome == Outcome::Completed),
            count(&|report| report.counts.failures > 0),
            reports.iter().map(|report| report.signers).sum::<usize>(),
            reports
                .iter()
                .map(|report| report.deviations)
                .sum::<usize>(),
            reports
                .iter()
                .map(|report| report.counts.tolerated_panics)
                .sum::<usize>(),
        );
    }

    /// I10: a replayed input fails, or passes, identically.
    #[test]
    fn replay_is_reproducible() {
        let run = || run_dkg_reshare(input(11, 2, SPLIT, ROTATE, 9));
        invariants::check_replay(run(), run());
    }

    /// I10 rejects two runs of one input that measured different things.
    /// The second run here is not a function of its input alone: an engine
    /// in it registers an epoch once more, as a restart would, which every
    /// other check accepts.
    #[test]
    #[should_panic(expected = "I10 violated: two runs of one input measured different things")]
    fn replay_that_measures_something_else_is_rejected() {
        let input = input(0, 1, WHOLE, STAY, 0);
        let first = run_dkg_reshare(input.clone());
        let (second, _) = execute(input, Fault::Reregister);
        assert_eq!(second.signers, first.signers + 1, "{second}");
        invariants::check_replay(first, second);
    }

    /// Whichever identity the scenario compromises, the input picks the
    /// identity outside the first committee among the other four, so both
    /// halves start with the compromised identity's share of the first
    /// output.
    #[test]
    fn compromised_identity_is_in_the_first_committee() {
        let signers = signers(RESHARE_IDENTITIES);
        for compromised in 0..RESHARE_IDENTITIES as usize {
            let outsiders: BTreeSet<u8> = (0..PEERS as u8)
                .map(|selected| outsider(compromised, selected))
                .collect();
            assert_eq!(outsiders.len(), PEERS, "{outsiders:?}");
            for selected in 0..=u8::MAX {
                let outsider = outsider(compromised, selected);
                assert!(outsiders.contains(&outsider));
                let session = Session::deal(
                    TestRng::new(u64::from(selected)),
                    signers.clone(),
                    &SessionControls {
                        epochs: 1,
                        sharing_mode: Mode::NonZeroCounter,
                        outsider,
                        rotations: STAY,
                        mailbox: ROOMY_MAILBOX,
                    },
                );
                assert!(
                    session.share(compromised).is_some(),
                    "compromised identity {compromised} is outside the first committee"
                );
            }
        }
    }

    /// A fault a negative control plants at the boundary the oracle
    /// observes. Unless a fault names another, the engine it is planted at
    /// is the first correct one that fits it, in identity order.
    #[derive(Clone, Copy)]
    enum Fault {
        /// Have the second correct engine report a second description of
        /// the second epoch, with the other outcome.
        Describe,
        /// Have an engine that holds a share of the second output register
        /// the second epoch once more as a member, without the share.
        Shareless,
        /// Have an engine that holds a share of the second output register
        /// the second epoch once more as a signer with a share of another
        /// output.
        ForeignShare,
        /// Give the engines another schedule than the oracle holds: the
        /// players of the third epoch's ceremony differ, and the second
        /// epoch's description names them.
        Reschedule,
        /// Give an engine that holds a share of both outputs, under the
        /// second epoch, the share it held of the first output.
        Keep,
        /// Give the engines a first output with another transcript summary
        /// than the one the oracle holds, and the same sharing.
        Resummarize,
        /// Panic in a task of an engine.
        EnginePanic,
        /// Panic in a task of no engine.
        HarnessPanic,
        /// Close the channels of an engine, so that it ends on its own.
        Sever,
        /// Have the first correct identity block the second.
        Block,
        /// Have an engine that holds a share of the second output register
        /// the second epoch once more with the material it registered it
        /// with.
        Reregister,
        /// Have an engine be delivered a block before the midpoint of the
        /// first epoch that carries an epoch description.
        Misplace,
    }

    /// The description of the second epoch the engine behind `records` was
    /// delivered.
    fn second_description(records: &Records) -> Info {
        records
            .deliveries()
            .into_iter()
            .find(|(epoch, _)| *epoch == Epoch::new(1))
            .expect("the engine reached the second epoch")
            .1
    }

    /// The first correct engine whose secret store held a share of the
    /// output of each of `epochs`.
    fn holder(run: &Planting<'_>, epochs: &[Epoch]) -> usize {
        run.correct
            .iter()
            .copied()
            .find(|engine| {
                let held = run.secrets[*engine].held();
                epochs
                    .iter()
                    .all(|epoch| held.iter().any(|(stored, _)| stored == epoch))
            })
            .expect("a correct engine held the shares")
    }

    impl Plant for Fault {
        fn configure(&mut self, session: &mut Session) {
            match self {
                Self::Reschedule => {
                    let committee = session.schedule.committee();
                    let outsider = session
                        .participants
                        .iter()
                        .position(|identity| committee.position(identity).is_none())
                        .expect("one identity is outside the first committee");
                    let mut rotations = STAY;
                    rotations[2] = Rotation::Replace(0);
                    session.schedule = Schedule::new(&session.participants, outsider, &rotations);
                }
                Self::Resummarize => {
                    session.genesis.output = resummarized(&session.genesis.output);
                }
                _ => {}
            }
        }

        async fn started(&mut self, run: &Planting<'_>) {
            let engine = run.correct[0];
            match self {
                Self::EnginePanic => {
                    let context = run.context.child("planted");
                    drop(
                        EngineContext::new(context, engine).spawn(|_| async { panic!("planted") }),
                    );
                }
                Self::HarnessPanic => {
                    drop(
                        run.context
                            .child("planted")
                            .spawn(|_| async { panic!("planted") }),
                    );
                }
                Self::Sever => {
                    // Registering a channel again closes the receiver the
                    // engine holds.
                    drop(reshare_stack::register(run.oracle, &run.participants[engine]).await);
                }
                _ => {}
            }
        }

        async fn ended(&mut self, run: &Planting<'_>) {
            let (first, second) = (Epoch::zero(), Epoch::new(1));
            match self {
                Self::Describe => {
                    let records = &run.records[run.correct[1]];
                    let mut info = second_description(records);
                    info.outcome = match info.outcome {
                        EpochOutcome::Success => EpochOutcome::Failure,
                        EpochOutcome::Failure => EpochOutcome::Success,
                    };
                    records.delivered(second, info);
                }
                Self::Shareless => {
                    let engine = holder(run, &[second]);
                    let info = second_description(&run.records[engine]);
                    run.records[engine].registered(
                        second,
                        SchemeInfo::new(
                            &run.participants[engine],
                            info.output.players().clone(),
                            info.output.public().clone(),
                            None,
                        ),
                    );
                }
                Self::ForeignShare => {
                    let engine = holder(run, &[second]);
                    let info = second_description(&run.records[engine]);
                    let players = info.output.players().clone();
                    let (_, shares) =
                        deal::<MockGroup, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, players)
                            .expect("a trusted deal must succeed");
                    let share = shares
                        .get_value(&run.participants[engine])
                        .expect("the engine is a player of the second output")
                        .clone();
                    run.records[engine].registered(
                        second,
                        SchemeInfo::Signer {
                            participants: info.output.players().clone(),
                            sharing: info.output.public().clone(),
                            share,
                        },
                    );
                }
                Self::Keep => {
                    let engine = holder(run, &[first, second]);
                    let secrets = &run.secrets[engine];
                    let (_, kept) = secrets
                        .held()
                        .into_iter()
                        .find(|(stored, _)| *stored == first)
                        .expect("the engine held a share of the first output");
                    secrets.plant(second, kept);
                }
                Self::Reregister => {
                    let engine = holder(run, &[second]);
                    let records = &run.records[engine];
                    let (_, registration) = records
                        .registrations()
                        .into_iter()
                        .find(|(epoch, _)| *epoch == second)
                        .expect("the engine registered the second epoch");
                    records.registered(second, registration);
                }
                Self::Block => {
                    let (blocker, blocked) = (run.correct[0], run.correct[1]);
                    let mut control = run.oracle.control(run.participants[blocker].clone());
                    block!(control, run.participants[blocked].clone(), "planted block");
                }
                Self::Misplace => {
                    let records = &run.records[run.correct[0]];
                    let info = second_description(records);
                    records.placed(Height::new(3), Some(&Payload::EpochInfo(info)));
                }
                _ => {}
            }
        }
    }

    /// Run the fixed input of one successful ceremony over a fixed committee
    /// with `fault` planted. Its scenario compromises the last identity, and
    /// the first is outside the committee, so engine 0 holds no share.
    fn planted(fault: Fault) -> ReshareReport {
        execute(input(0, 1, WHOLE, STAY, 0), fault).0
    }

    /// The fixed input of one ceremony over a fixed committee that fails: a
    /// sustained scenario without a bound on its prefix names one leader for
    /// the whole epoch, and too few correct dealers get a log into a block.
    fn failing() -> DkgReshareFuzzInput {
        DkgReshareFuzzInput {
            sustained: true,
            prefix: None,
            ..input(0, 1, WHOLE, STAY, 0)
        }
    }

    #[test]
    fn fixed_inputs_of_the_controls_hold_invariants() {
        let report = measured(input(0, 1, WHOLE, STAY, 0));
        assert_eq!(report.counts.failures, 0, "{report}");
        let report = run_dkg_reshare(failing());
        println!("{report}");
        assert_eq!(report.outcome, Outcome::Completed, "{report}");
        assert_eq!(report.counts.failures, 1, "{report}");
        assert!(report.counts.carried > 0, "{report}");
    }

    #[test]
    #[should_panic(
        expected = "I1 violated: engine 0 and engine 1 disagree on the description of epoch 1"
    )]
    fn description_that_differs_between_engines_is_rejected() {
        planted(Fault::Describe);
    }

    /// Only the check of registered shares rejects this registration: it
    /// names the agreed sharing and the engine's own place among the
    /// players.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 registered the scheme of epoch 1 without the share it \
                    holds for it"
    )]
    fn registration_without_the_held_share_is_rejected() {
        planted(Fault::Shareless);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: the share engine 1 holds for epoch 1 does not match the \
                    output's partial public key"
    )]
    fn registered_share_of_another_output_is_rejected() {
        planted(Fault::ForeignShare);
    }

    #[test]
    #[should_panic(expected = "I4 violated: the next players of epoch 1 are")]
    fn next_players_off_the_schedule_are_rejected() {
        planted(Fault::Reschedule);
    }

    #[test]
    #[should_panic(
        expected = "I5 violated: the shares engines [2, 3] held before the reshare into epoch 1, \
                    mixed with the shares engines [1] hold after it, reconstruct the key"
    )]
    fn share_kept_through_the_reshare_is_rejected() {
        planted(Fault::Keep);
    }

    #[test]
    #[should_panic(
        expected = "I6 violated: the failed ceremony did not carry the previous \
                               output into epoch 1 unchanged"
    )]
    fn failed_ceremony_that_changes_the_output_is_rejected() {
        execute(failing(), Fault::Resummarize);
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engine 0 panicked")]
    fn engine_panic_is_rejected() {
        planted(Fault::EnginePanic);
    }

    #[test]
    #[should_panic(expected = "I8 violated: a task of no engine panicked")]
    fn harness_panic_is_rejected() {
        planted(Fault::HarnessPanic);
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [0] stopped before the run ended")]
    fn engine_that_stops_on_its_own_is_rejected() {
        planted(Fault::Sever);
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_is_rejected() {
        planted(Fault::Block);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 0 was delivered a finalized block at height 3, before \
                    the midpoint of epoch 0, that carries an epoch description"
    )]
    fn description_before_the_midpoint_is_rejected() {
        planted(Fault::Misplace);
    }
}

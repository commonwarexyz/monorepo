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
//! identity's share of the first output, if it has one. Its Simplex, marshal,
//! and dissemination channels are split per view by the selected twins
//! scenario for the first views of every epoch, its DKG channel is split by
//! the input's mask for each epoch's ceremony, and its secondary half runs the
//! faulty application. The scenario's scripted leaders lead the views they
//! are scripted for in every epoch whose committee holds them.
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
    reshare_network::{Masks, Scripted, Simplex, Twins},
    reshare_stack::{self, Config},
    runner::{self, Report},
    signers,
    store::Secrets,
};
use crate::stateful::{
    network::{select_case, shared_router},
    runner::{LINK, Panic, network_with},
};
use commonware_consensus::types::Epoch;
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
}

impl fmt::Display for ReshareReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} asked={} epochs={} correct_nodes={} boundaries={} successes={} \
             failures={} agreements={} registrations={} shares={} players={} \
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
    execute(input).0
}

/// Run `input` and return what the run measured with every panic it raised,
/// each of which was tolerated.
fn execute(input: DkgReshareFuzzInput) -> (ReshareReport, Vec<Panic>) {
    let entropy = input.raw_bytes.clone();
    let asked = input.epochs;
    let (observed, panics) =
        runner::execute(entropy.clone(), |context| run(context, input, entropy));

    // Measurement point, outside the runtime so a violation is never caught.
    let Some(observed) = observed else {
        invariants::check_panics(&panics, &[]);
        let report = ReshareReport {
            outcome: Outcome::NoCase,
            asked,
            deviations: 0,
            counts: ReshareCounts::default(),
        };
        return (report, panics);
    };
    let tolerated_panics = invariants::check_panics(&panics, &observed.halves);
    invariants::check_engines_running(&observed.stopped);
    let counts = invariants::check_reshare(&observed.reshare, &observed.blocked);
    let report = ReshareReport {
        outcome: observed.outcome,
        asked,
        deviations: observed.deviations,
        counts: ReshareCounts {
            tolerated_panics,
            ..counts
        },
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

async fn run(
    mut context: deterministic::Context,
    input: DkgReshareFuzzInput,
    entropy: Vec<u8>,
) -> Option<Observations> {
    let signers = signers(RESHARE_IDENTITIES);
    let participants: Arc<[PublicKey]> = public_keys(&signers);
    let oracle = network_with(&context, &participants, LINK, TRACKED_PEER_SETS).await;

    // Draw the twins scenario from the tape.
    let (compromised, scenario) = select_case(
        entropy.clone(),
        participants.len(),
        input.sustained,
        input.case_selector,
    )?;

    // The first output comes from a trusted deal among the first committee.
    let controls = SessionControls {
        epochs: input.epochs,
        sharing_mode: input.sharing_mode,
        outsider: input.outsider,
        rotations: input.rotations,
    };
    let session = Session::deal(&mut context, signers, &controls);

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
    let elector = Scripted::new(&scenario, &participants);
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
    let split = Twins::new(participants.clone(), scenario);
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
        },
        votes_secondary,
        certificates_secondary,
        resolver_secondary,
        backfill_secondary,
        broadcast_secondary,
        dkg_secondary,
        (raw.probe.0, probe_rx_secondary),
    ));
    let (outcome, stopped) = runner::watch(&context, engines, waiters, RESHARE_RUN_TIMEOUT).await;

    // Both halves of the compromised identity are excluded from the records.
    let blocked = runner::blocked(&oracle).await;
    let nodes = correct
        .into_iter()
        .map(|engine| {
            Resharer::observed(
                engine,
                participants[engine].clone(),
                &records[engine],
                secrets[engine].held(),
            )
        })
        .collect();
    Some(Observations {
        outcome,
        reshare: Reshare {
            genesis: session.genesis,
            schedule: session.schedule,
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
        DkgMask, MAX_EPOCHS, Rotation, Side,
        fixtures::{self, ROTATE, STAY, contradicted, decode, tape},
        reshare_input::ROTATIONS,
    };
    use commonware_cryptography::bls12381::primitives::sharing::Mode;

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
            epochs,
            masks,
            sharing_mode: if seed.is_multiple_of(2) {
                Mode::NonZeroCounter
            } else {
                Mode::RootsOfUnity
            },
            outsider: seed % RESHARE_IDENTITIES as u8,
            rotations,
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
            let (report, panics) = execute(input);
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
            fixtures::sample::over(&inputs, |input| contradicted(&execute(input.clone()).1));
        let shown: Vec<usize> = (0..inputs.len()).filter(|input| shown[*input]).collect();
        println!(
            "CONTRADICTED {} of {}: {shown:?}",
            shown.len(),
            inputs.len()
        );
    }

    /// Inputs as libFuzzer first produces them decode to whole sessions that
    /// hold the invariants.
    #[test]
    fn short_inputs_hold_invariants() {
        for byte in [0x00u8, 0x5a, 0xa9, 0xff] {
            measured(decode(&[byte]));
        }
    }

    /// I10: a replayed input fails, or passes, identically.
    #[test]
    fn replay_is_reproducible() {
        let run = || run_dkg_reshare(input(11, 2, SPLIT, ROTATE, 9));
        assert_eq!(run(), run());
    }
}

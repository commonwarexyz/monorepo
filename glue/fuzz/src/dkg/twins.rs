//! The bootstrap Twins driver: five engines over four identities, no crashes.
//!
//! Three identities are correct and run one real bootstrap engine each. The
//! compromised identity runs two, sharing its key, each on its own storage
//! partitions and with its own secret store, so the two halves deal
//! differently under one identity. Its Simplex, marshal, and dissemination
//! channels are split per view by the selected twins scenario for the first
//! views of the chain, and its DKG channel is split by the input's mask for
//! the whole ceremony.
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
    invariants::{self, Ceremony, Counts, Ending, Observed},
    network::{Mask, Twins, halve},
    public_keys,
    runner::{self, Report},
    stack::{self, Completion, MAX_SUPPORTED_MODE},
    store::Secrets,
};
use crate::stateful::{
    network::select_case,
    runner::{Panic, network},
};
use commonware_consensus::types::Epoch;
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{channel::oneshot, ordered::Set, sync::Mutex};
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
    execute(input).0
}

/// Run `input` and return what the run measured with every panic it raised,
/// each of which was tolerated.
fn execute(input: DkgBootstrapFuzzInput) -> (BootstrapReport, Vec<Panic>) {
    let entropy = input.raw_bytes.clone();
    let (observed, panics) =
        runner::execute(entropy.clone(), |context| run(context, input, entropy));

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
        invariants::check_bootstrap(&observed.ceremony, &observed.committee, &observed.blocked);
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
    ceremony: Ceremony,
    /// The identities the ceremony is among, in identity order.
    committee: Arc<[PublicKey]>,
    /// The engines of the compromised identity.
    halves: [usize; 2],
    blocked: Vec<(PublicKey, PublicKey)>,
    /// Correct engines that stopped before the run ended.
    stopped: Vec<usize>,
}

/// One engine's completion, recorded when the engine reports it.
type Reported = Arc<Mutex<Option<Ending>>>;

/// Record `completion` into `reported` once the engine sends it.
fn await_completion(
    context: deterministic::Context,
    completion: oneshot::Receiver<Completion>,
    reported: Reported,
) -> Handle<()> {
    context.spawn(move |_| async move {
        // An engine that stops without reporting leaves its record empty.
        let Ok(completion) = completion.await else {
            return std::future::pending().await;
        };
        *reported.lock() = Some(stack::ending(completion));
    })
}

async fn run(
    context: deterministic::Context,
    input: DkgBootstrapFuzzInput,
    entropy: Vec<u8>,
) -> Option<Observations> {
    let signers = identities();
    let participants: Arc<[PublicKey]> = public_keys(&signers);
    let committee = Set::from_iter_dedup(participants.iter().cloned());
    let oracle = network(&context, &participants).await;

    // Draw the twins scenario from the tape.
    let (compromised, scenario) = select_case(
        entropy,
        participants.len(),
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
    let split = Twins::new(participants.clone(), scenario, MAX_SUPPORTED_MODE);
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
    let (outcome, stopped) = runner::watch(&context, engines, waiters, BOOTSTRAP_RUN_TIMEOUT).await;

    // Both halves of the compromised identity are excluded from the records.
    let blocked = runner::blocked(&oracle).await;
    let ceremony = Ceremony {
        epoch: Epoch::zero(),
        nodes: correct
            .into_iter()
            .map(|(engine, reported)| Observed {
                engine,
                identity: participants[engine].clone(),
                ending: reported.lock().clone(),
                share: secrets[engine].share(Epoch::zero()),
            })
            .collect(),
    };
    Some(Observations {
        outcome,
        ceremony,
        halves: [compromised, SECONDARY_ENGINE],
        committee: participants,
        blocked,
        stopped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{
            DkgMask, Side,
            fixtures::{self, contradicted, tape},
        },
        stateful::runner::tolerating,
    };
    use commonware_cryptography::bls12381::primitives::sharing::Mode;
    use commonware_runtime::{Clock as _, Runner as _};
    use std::time::Duration;

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

    /// A panic in a task no handle watches is recorded and judged.
    #[test]
    #[should_panic(expected = "I8 violated: a task of no engine panicked")]
    fn detached_task_panic_is_rejected() {
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, panics) = tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                drop(
                    context
                        .child("detached")
                        .spawn(|_| async { panic!("boom") }),
                );
                context.sleep(Duration::from_millis(10)).await;
            })
        });
        result.expect("the root task returns");
        invariants::check_panics(&panics, &[0, SECONDARY_ENGINE]);
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
            let (report, panics) = execute(input);
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
            fixtures::sample::over(&inputs, |input| contradicted(&execute(input.clone()).1));
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
        assert_eq!(run(), run());
    }
}

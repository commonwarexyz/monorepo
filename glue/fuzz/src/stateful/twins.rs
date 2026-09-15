//! The twins driver: five engines over four identities, no crashes.
//!
//! The compromised identity runs two full node stacks sharing one signing key,
//! its channels split per view by the selected twins scenario, with the correct
//! application on the primary half and the faulty one on the secondary. Crashes
//! belong to the restart driver, which runs a cluster of four correct nodes.
//!
//! The driver runs once over the standard marshal and, as a separate target,
//! once over the coding marshal, where blocks reach marshal as erasure-coded
//! shards and the stateful actor is driven through `Marshaled` rather than
//! `Deferred`. The scenario, the applications, and the invariants are the same.

use super::{
    MAX_CASES, NUM_IDENTITIES, PREFIX_ROUNDS, RUN_TIMEOUT,
    app::{Block, CorrectApp, FaultSchedule, FaultyApp},
    backend::{Any, Backend},
    input::StatefulTwinsFuzzInput,
    invariants::EngineObservations,
    marshal::Marshal,
    network::{
        backfill_forwarder, backfill_router, broadcast_forwarder, broadcast_router,
        certificate_forwarder, certificate_router, resolver_forwarder, resolver_router,
        shared_router, vote_forwarder, vote_router,
    },
    runner::{self, CorrectEngine, NodeConfig, Outcome, RunReport},
    stack::{
        EngineChannels, EngineConfig, SYNC_CONFIG, register_channels, round_robin, spawn_engine,
    },
};
use commonware_consensus::{
    marshal::{ancestry::BlockProvider, core::Mailbox as MarshalMailbox},
    simplex::mocks::twins,
    types::View,
};
use commonware_macros::select;
use commonware_runtime::{Clock, Runner as _, Supervisor as _, deterministic};
use commonware_utils::FuzzRng;
use futures::future::join_all;

/// Label the standard-marshal driver reports under.
#[cfg(feature = "stateful-cert-mock-twins")]
const TARGET: &str = "glue-stateful-twins";

/// Label the coding-marshal driver reports under.
#[cfg(feature = "stateful-cert-mock-twins-coding")]
const CODING_TARGET: &str = "glue-stateful-twins-coding";

/// The engine index of the compromised identity's secondary half.
const SECONDARY_ENGINE: usize = NUM_IDENTITIES as usize;

/// Engines in the cluster: one per identity plus the compromised half.
const NUM_ENGINES: usize = SECONDARY_ENGINE + 1;

/// libFuzzer entry point over the standard marshal.
#[cfg(feature = "stateful-cert-mock-twins")]
pub fn fuzz_stateful_cert_mock_twins(input: StatefulTwinsFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_twins(input));
}

/// Run one twins scenario over the standard marshal and return what it
/// measured.
///
/// A run is fully determined by its input bytes.
#[cfg(feature = "stateful-cert-mock-twins")]
pub fn run_stateful_twins(input: StatefulTwinsFuzzInput) -> RunReport {
    execute::<Any, super::marshal::Standard>(TARGET, input)
}

/// libFuzzer entry point over the coding marshal.
#[cfg(feature = "stateful-cert-mock-twins-coding")]
pub fn fuzz_stateful_cert_mock_twins_coding(input: StatefulTwinsFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_twins_coding(input));
}

/// Run one twins scenario over the coding marshal and return what it
/// measured.
///
/// A run is fully determined by its input bytes.
#[cfg(feature = "stateful-cert-mock-twins-coding")]
pub fn run_stateful_twins_coding(input: StatefulTwinsFuzzInput) -> RunReport {
    execute::<Any, super::marshal::Coding>(CODING_TARGET, input)
}

/// Run one twins scenario over the five-engine cluster. A run is fully
/// determined by its input bytes.
fn execute<B, M>(target: &'static str, input: StatefulTwinsFuzzInput) -> RunReport
where
    B: Backend,
    M: Marshal,
    MarshalMailbox<super::Scheme, M::Variant>: BlockProvider<Block = Block<M>>,
{
    let entropy = input.raw_bytes.clone();
    let config = deterministic::Config::new().with_rng(FuzzRng::new(entropy.clone()));
    deterministic::Runner::new(config).start(|context| run::<B, M>(context, target, input, entropy))
}

async fn run<B, M>(
    mut context: deterministic::Context,
    target: &'static str,
    input: StatefulTwinsFuzzInput,
    entropy: Vec<u8>,
) -> RunReport
where
    B: Backend,
    M: Marshal,
    MarshalMailbox<super::Scheme, M::Variant>: BlockProvider<Block = Block<M>>,
{
    let cluster = runner::setup::<B, M>(&mut context).await;
    let participants = cluster.participants.clone();

    // Draw the twins scenario from the tape.
    let mut scenario_rng = FuzzRng::new(entropy.clone());
    let cases = twins::cases(
        &mut scenario_rng,
        twins::Framework {
            participants: participants.len(),
            faults: 1,
            rounds: PREFIX_ROUNDS,
            mode: if input.sustained {
                twins::Mode::Sustained
            } else {
                twins::Mode::Sampled
            },
            max_cases: MAX_CASES,
        },
    );
    if cases.is_empty() {
        return RunReport::skipped(target, B::NAME, M::NAME, Outcome::NoCase);
    }
    let selected = usize::from(input.case_selector) % cases.len();
    let case = cases
        .into_iter()
        .nth(selected)
        .expect("selected twins case must exist");
    let compromised = *case
        .compromised
        .first()
        .expect("twins case must compromise one identity");
    assert!(
        compromised < participants.len(),
        "twins case compromised an identity outside the validator set"
    );
    let scenario = case.scenario;
    let term_length = input.term_length;
    let elector = twins::Elector::new(round_robin(term_length), &scenario, participants.len());

    let observations: Vec<EngineObservations> = (0..NUM_ENGINES)
        .map(|_| EngineObservations::new())
        .collect();

    // Correct identities.
    let mut correct = Vec::with_capacity(participants.len() - 1);
    for (index, node) in observations.iter().enumerate().take(participants.len()) {
        if index == compromised {
            continue;
        }
        correct.push(
            CorrectEngine::<B, M, _>::start(
                &context,
                &cluster,
                index,
                NodeConfig::new(elector.clone(), None),
                node.clone(),
            )
            .await,
        );
    }

    // The compromised identity. Its channels are split in two, and its two
    // halves run the correct and the faulty application respectively.
    let identity = participants[compromised].clone();
    let scheme = cluster.schemes[compromised].clone();
    let raw = register_channels(&cluster.oracle, &identity).await;
    let node_context = context
        .child("compromised")
        .with_attribute("index", compromised);

    let (vote_primary, vote_secondary) = raw.vote.0.split_with(vote_forwarder::<M>(
        participants.clone(),
        scenario.clone(),
        term_length,
    ));
    let (vote_rx_primary, vote_rx_secondary) = raw.vote.1.split_with(
        node_context.child("vote_split"),
        vote_router::<M>(participants.clone(), scenario.clone(), term_length),
    );
    let (certificate_primary, certificate_secondary) =
        raw.certificate.0.split_with(certificate_forwarder::<M>(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ));
    let (certificate_rx_primary, certificate_rx_secondary) = raw.certificate.1.split_with(
        node_context.child("certificate_split"),
        certificate_router::<M>(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ),
    );
    let (resolver_primary, resolver_secondary) =
        raw.simplex_resolver.0.split_with(resolver_forwarder::<M>(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ));
    let (resolver_rx_primary, resolver_rx_secondary) = raw.simplex_resolver.1.split_with(
        node_context.child("resolver_split"),
        resolver_router::<M>(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ),
    );
    let (backfill_primary, backfill_secondary) = raw.backfill.0.split_with(backfill_forwarder(
        participants.clone(),
        scenario.clone(),
        term_length,
    ));
    let (backfill_rx_primary, backfill_rx_secondary) = raw.backfill.1.split_with(
        node_context.child("backfill_split"),
        backfill_router(participants.clone(), scenario.clone(), term_length),
    );
    let (broadcast_primary, broadcast_secondary) = raw.broadcast.0.split_with(
        broadcast_forwarder::<M>(participants.clone(), scenario.clone(), term_length),
    );
    let (broadcast_rx_primary, broadcast_rx_secondary) = raw.broadcast.1.split_with(
        node_context.child("broadcast_split"),
        broadcast_router::<M>(participants.clone(), scenario.clone(), term_length),
    );
    let (database_rx_primary, database_rx_secondary) = raw
        .database
        .1
        .split_with(node_context.child("database_split"), shared_router());

    // No node discovers or serves a floor in this driver, so the compromised
    // identity's probe channel goes unused rather than split.
    let primary_channels = EngineChannels {
        vote: (vote_primary, vote_rx_primary),
        certificate: (certificate_primary, certificate_rx_primary),
        simplex_resolver: (resolver_primary, resolver_rx_primary),
        backfill: (backfill_primary, backfill_rx_primary),
        broadcast: (broadcast_primary, broadcast_rx_primary),
        database: (raw.database.0.clone(), database_rx_primary),
        probe: None,
    };
    let secondary_channels = EngineChannels {
        vote: (vote_secondary, vote_rx_secondary),
        certificate: (certificate_secondary, certificate_rx_secondary),
        simplex_resolver: (resolver_secondary, resolver_rx_secondary),
        backfill: (backfill_secondary, backfill_rx_secondary),
        broadcast: (broadcast_secondary, broadcast_rx_secondary),
        database: (raw.database.0, database_rx_secondary),
        probe: None,
    };

    drop(spawn_engine::<B, M, _, _, _, _, _, _, _>(
        node_context.child("primary"),
        cluster.oracle.clone(),
        EngineConfig {
            identity: identity.clone(),
            scheme: scheme.clone(),
            elector: elector.clone(),
            genesis: cluster.genesis.clone(),
            partition_prefix: format!("engine-{compromised}-primary"),
            application: CorrectApp::<B, M>::new(
                cluster.genesis.clone(),
                observations[compromised].clone(),
            ),
            observations: observations[compromised].clone(),
            prune: None,
            sync: SYNC_CONFIG,
            state_sync: false,
        },
        primary_channels,
    ));

    let mut fault_rng = FuzzRng::new(entropy);
    let schedule = FaultSchedule::new(&mut fault_rng, input.faults);
    drop(spawn_engine::<B, M, _, _, _, _, _, _, _>(
        node_context.child("secondary"),
        cluster.oracle.clone(),
        EngineConfig {
            identity,
            scheme,
            elector,
            genesis: cluster.genesis.clone(),
            partition_prefix: format!("engine-{compromised}-secondary"),
            application: FaultyApp::new(
                CorrectApp::<B, M>::new(
                    cluster.genesis.clone(),
                    observations[SECONDARY_ENGINE].clone(),
                ),
                schedule,
            ),
            observations: observations[SECONDARY_ENGINE].clone(),
            prune: None,
            sync: SYNC_CONFIG,
            state_sync: false,
        },
        secondary_channels,
    ));

    // The scenario scripts a partition for each of its rounds and prescribes
    // none afterwards, at which point both halves address every identity.
    // Counting only heights past that boundary keeps a run from finishing
    // before every scripted round has been traversed.
    let scripted_through = View::new(PREFIX_ROUNDS as u64 * term_length.get());
    let waiters = runner::waiters(
        &context,
        &correct,
        usize::from(input.required_heights),
        scripted_through,
    );
    let outcome = select! {
        _ = context.sleep(RUN_TIMEOUT) => Outcome::Timeout,
        _ = join_all(waiters) => Outcome::Suffix,
    };

    // Measurement point. Both halves of the compromised identity are excluded.
    runner::measure(
        target,
        outcome,
        &correct,
        &observations,
        &cluster.genesis,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::{MAX_REQUIRED_HEIGHTS, MAX_TERM_LENGTH, app::FaultArming};
    use commonware_consensus::types::TermLength;
    use commonware_utils::NZU32;

    /// Every deviation the faulty application may take.
    const ALL_FAULTS: FaultArming = FaultArming {
        reject_verification: true,
        abstain_verification: true,
        divergent_proposal: true,
        decline_proposal: true,
    };

    /// The compromised identity deviates only at the message layer.
    const NO_FAULTS: FaultArming = FaultArming {
        reject_verification: false,
        abstain_verification: false,
        divergent_proposal: false,
        decline_proposal: false,
    };

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn input(
        case_selector: u16,
        sustained: bool,
        faults: FaultArming,
        required_heights: u8,
        term_length: u32,
        seed: u8,
    ) -> StatefulTwinsFuzzInput {
        StatefulTwinsFuzzInput {
            case_selector,
            sustained,
            faults,
            required_heights,
            term_length: TermLength::new(NZU32!(term_length)),
            raw_bytes: tape(seed),
        }
    }

    /// The driver's test suite, run once per marshal variant the crate is
    /// built with.
    macro_rules! twins_suite {
        ($name:ident, $run:path, $feature:literal) => {
            #[cfg(feature = $feature)]
            mod $name {
                use super::*;

                /// Runs one fixed input and asserts the checks were not vacuous.
                fn measured(input: StatefulTwinsFuzzInput) -> RunReport {
                    let report = $run(input);
                    println!("{report}");
                    assert!(
                        report.measured(),
                        "run measured nothing and must not be counted as passing: {report}"
                    );
                    report
                }

                #[test]
                fn sampled_partitions_hold_invariants() {
                    measured(input(0, false, ALL_FAULTS, 1, 1, 0));
                }

                #[test]
                fn sustained_partitions_hold_invariants() {
                    measured(input(0, true, ALL_FAULTS, 2, 1, 0));
                }

                #[test]
                fn disarmed_adversary_holds_invariants() {
                    measured(input(0, false, NO_FAULTS, 1, 1, 0));
                }

                #[test]
                fn long_terms_hold_invariants() {
                    measured(input(3, true, ALL_FAULTS, 2, 4, 7));
                }

                /// The target explores a scenario per case selector; every one
                /// of them is a regression case.
                #[test]
                fn selected_cases_hold_invariants() {
                    for case_selector in 0..8u16 {
                        let report = $run(input(
                            case_selector,
                            case_selector % 2 == 1,
                            ALL_FAULTS,
                            u8::try_from(case_selector % u16::from(MAX_REQUIRED_HEIGHTS))
                                .expect("fits")
                                + 1,
                            u32::from(case_selector % MAX_TERM_LENGTH as u16) + 1,
                            u8::try_from(case_selector).expect("fits"),
                        ));
                        println!("case {case_selector}: {report}");
                        assert!(
                            report.counts.correct_nodes > 0,
                            "case {case_selector} observed no correct node: {report}"
                        );
                    }
                }

                /// The twins driver never crashes a node.
                #[test]
                fn no_restarts_occur() {
                    assert_eq!(
                        measured(input(1, false, ALL_FAULTS, 2, 2, 3))
                            .counts
                            .restarts,
                        0
                    );
                }

                /// I6: a replayed input fails, or passes, identically.
                #[test]
                fn replay_is_reproducible() {
                    let first = $run(input(2, false, ALL_FAULTS, 2, 3, 11));
                    let second = $run(input(2, false, ALL_FAULTS, 2, 3, 11));
                    assert_eq!(first, second, "replaying an input changed what it measured");
                }
            }
        };
    }

    twins_suite!(standard, run_stateful_twins, "stateful-cert-mock-twins");
    twins_suite!(
        coding,
        run_stateful_twins_coding,
        "stateful-cert-mock-twins-coding"
    );

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(0, false, ALL_FAULTS, 1, 1, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}

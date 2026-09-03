//! The twins driver: scenario selection, engine startup, restart scheduling,
//! and the measurement point.
//!
//! The run ends when every correct node has applied the required number of
//! heights past the adversarial prefix, or when its bounded timeout expires,
//! whichever comes first. Completion is keyed on application rather than on
//! delivery, because the database commitment I2 compares is written only once
//! the batch is applied. Because
//! quorum is three of four, a crash during a partition can legitimately stall
//! the run, so termination is by timeout and never by a liveness wait; the
//! invariants are then checked over whatever was observed, including nothing.

use super::{
    Databases, MAX_CASES, NAMESPACE, NUM_IDENTITIES, PREFIX_ROUNDS, PublicKey, RESTART_DOWNTIME,
    RUN_TIMEOUT, Scheme,
    app::{Block, CorrectApp, FaultSchedule, FaultyApp},
    input::StatefulTwinsFuzzInput,
    invariants::{self, Counts, EngineObservations},
    network::{
        backfill_forwarder, backfill_router, broadcast_forwarder, broadcast_router,
        certificate_forwarder, certificate_router, resolver_forwarder, resolver_router,
        shared_router, vote_forwarder, vote_router,
    },
    stack::{Elector, EngineChannels, EngineConfig, register_channels, round_robin, spawn_engine},
};
use commonware_consensus::{
    simplex::mocks::{scheme as scheme_mocks, twins},
    types::View,
};
use commonware_cryptography::Digestible;
use commonware_glue::stateful::db::DatabaseSet;
use commonware_macros::select;
use commonware_p2p::simulated::{
    Config as NetworkConfig, Link, Network as SimulatedNetwork, Oracle,
};
use commonware_runtime::{
    Clock, Handle, Runner as _, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{
    FuzzRng, NZUsize, probability,
    sync::{Mutex, Once},
};
use futures::future::join_all;
use rand::RngExt as _;
use std::{collections::BTreeSet, fmt, panic, sync::Arc, time::Duration};

/// Environment variable enabling the per-run report.
const REPORT_ENV: &str = "GLUE_FUZZ_LOG";

/// Every directed link stays up for the whole run; the twins scenario owns
/// connectivity, and it does so by splitting channels rather than by
/// manipulating links.
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// The engine index of the compromised identity's secondary half.
const SECONDARY_ENGINE: usize = NUM_IDENTITIES as usize;

/// Engines in the cluster: one per identity plus the compromised identity's
/// secondary half.
const NUM_ENGINES: usize = SECONDARY_ENGINE + 1;

/// Why a run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every correct node applied its required suffix heights.
    Suffix,
    /// The run's bounded timeout expired.
    Timeout,
    /// The twins generator produced no case, so nothing ran.
    NoCase,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suffix => f.write_str("suffix"),
            Self::Timeout => f.write_str("timeout"),
            Self::NoCase => f.write_str("no-case"),
        }
    }
}

/// What one run observed, so a run that measured nothing is never mistaken for
/// a run that found nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunReport {
    /// Why the run stopped.
    pub outcome: Outcome,
    /// How much each check compared.
    pub counts: Counts,
}

impl RunReport {
    const fn skipped(outcome: Outcome) -> Self {
        Self {
            outcome,
            counts: Counts {
                correct_nodes: 0,
                chain_heights: 0,
                state_comparisons: 0,
                verdict_comparisons: 0,
                restarts: 0,
            },
        }
    }

    /// Whether every check compared something.
    pub const fn measured(&self) -> bool {
        self.counts.measured()
    }
}

impl fmt::Display for RunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[glue-stateful-twins] outcome={} correct_nodes={} chain_heights={} \
             state_comparisons={} verdict_comparisons={} restarts={}{}",
            self.outcome,
            self.counts.correct_nodes,
            self.counts.chain_heights,
            self.counts.state_comparisons,
            self.counts.verdict_comparisons,
            self.counts.restarts,
            if self.measured() {
                ""
            } else {
                " UNMEASURED (nothing was compared)"
            },
        )
    }
}

/// The tape of the run in flight, so the panic hook can name the reproducing
/// input.
static IN_FLIGHT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Print the reproducing input before the process aborts.
///
/// The hook is installed ahead of libFuzzer's, which prints and aborts, so
/// anything queued after it would never reach the terminal.
fn install_input_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let tape = IN_FLIGHT.lock().clone();
            if !tape.is_empty() {
                eprintln!("Panicked with raw_bytes: {tape:?}");
            }
            previous(info);
        }));
    });
}

/// libFuzzer entry point.
pub fn fuzz_stateful_cert_mock_twins(input: StatefulTwinsFuzzInput) {
    install_input_panic_hook();
    IN_FLIGHT.lock().clone_from(&input.raw_bytes);
    let report = run_stateful_twins(input);

    // A run that measured nothing is always reported, so it is never silently
    // counted as a run that found nothing.
    if !report.measured() || std::env::var_os(REPORT_ENV).is_some() {
        eprintln!("{report}");
    }
}

/// Run one scenario and return what it measured.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_twins(input: StatefulTwinsFuzzInput) -> RunReport {
    let entropy = input.raw_bytes.clone();
    let config = deterministic::Config::new().with_rng(FuzzRng::new(entropy.clone()));
    deterministic::Runner::new(config).start(|context| run(context, input, entropy))
}

/// One correct identity's engine, retained so a restart can rebuild it on the
/// same storage partitions under the same key.
struct CorrectEngine {
    engine: usize,
    identity: PublicKey,
    scheme: Scheme,
    partition: String,
    observations: EngineObservations,
    handle: Handle<()>,
}

async fn run(
    mut context: deterministic::Context,
    input: StatefulTwinsFuzzInput,
    entropy: Vec<u8>,
) -> RunReport {
    let fixture =
        scheme_mocks::fixture_with::<false, true, true, _>(&mut context, NAMESPACE, NUM_IDENTITIES);
    let participants: Arc<[PublicKey]> = fixture.participants.clone().into();
    let schemes = fixture.schemes;

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
        return RunReport::skipped(Outcome::NoCase);
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

    // Network. Every directed link stays up for the whole run.
    let (network, oracle) = SimulatedNetwork::new_with_peers(
        context.child("network"),
        NetworkConfig {
            max_size: 1024 * 1024,
            max_peers_per_set: NZUsize!(participants.len()),
            disconnect_on_block: false,
            tracked_peer_sets: NZUsize!(1),
        },
        participants.iter().cloned(),
    )
    .await;
    network.start();
    for sender in participants.iter() {
        for receiver in participants.iter() {
            if sender == receiver {
                continue;
            }
            oracle
                .add_link(sender.clone(), receiver.clone(), LINK)
                .await
                .expect("link must be installed");
        }
    }

    // Genesis. Every engine starts from the same block with no finalized floor.
    let initial = <Databases as DatabaseSet<deterministic::Context>>::initial_sync_targets();
    let genesis = Block::genesis(participants[0].clone(), initial.root, initial.range);
    let genesis_digest = genesis.digest();

    let observations: Vec<EngineObservations> = (0..NUM_ENGINES)
        .map(|_| EngineObservations::new())
        .collect();

    // Correct identities.
    let mut correct = Vec::with_capacity(participants.len() - 1);
    for (index, identity) in participants.iter().enumerate() {
        if index == compromised {
            continue;
        }
        let partition = format!("engine-{index}");
        let node = CorrectEngine {
            engine: index,
            identity: identity.clone(),
            scheme: schemes[index].clone(),
            partition: partition.clone(),
            observations: observations[index].clone(),
            handle: start_correct(
                &context,
                &oracle,
                index,
                identity.clone(),
                schemes[index].clone(),
                &elector,
                &genesis,
                partition,
                observations[index].clone(),
            )
            .await,
        };
        correct.push(node);
    }

    // The compromised identity. Its channels are split in two, and its two
    // halves run the correct and the faulty application respectively.
    let identity = participants[compromised].clone();
    let scheme = schemes[compromised].clone();
    let raw = register_channels(&oracle, &identity).await;
    let node_context = context
        .child("compromised")
        .with_attribute("index", compromised);

    let (vote_primary, vote_secondary) = raw.vote.0.split_with(vote_forwarder(
        participants.clone(),
        scenario.clone(),
        term_length,
    ));
    let (vote_rx_primary, vote_rx_secondary) = raw.vote.1.split_with(
        node_context.child("vote_split"),
        vote_router(participants.clone(), scenario.clone(), term_length),
    );
    let (certificate_primary, certificate_secondary) =
        raw.certificate.0.split_with(certificate_forwarder(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ));
    let (certificate_rx_primary, certificate_rx_secondary) = raw.certificate.1.split_with(
        node_context.child("certificate_split"),
        certificate_router(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ),
    );
    let (resolver_primary, resolver_secondary) =
        raw.simplex_resolver.0.split_with(resolver_forwarder(
            participants.clone(),
            scenario.clone(),
            term_length,
            scheme.clone(),
        ));
    let (resolver_rx_primary, resolver_rx_secondary) = raw.simplex_resolver.1.split_with(
        node_context.child("resolver_split"),
        resolver_router(
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
    let (broadcast_primary, broadcast_secondary) = raw.broadcast.0.split_with(broadcast_forwarder(
        participants.clone(),
        scenario.clone(),
        term_length,
    ));
    let (broadcast_rx_primary, broadcast_rx_secondary) = raw.broadcast.1.split_with(
        node_context.child("broadcast_split"),
        broadcast_router(participants.clone(), scenario.clone(), term_length),
    );
    let (database_rx_primary, database_rx_secondary) = raw
        .database
        .1
        .split_with(node_context.child("database_split"), shared_router());

    let primary_channels = EngineChannels {
        vote: (vote_primary, vote_rx_primary),
        certificate: (certificate_primary, certificate_rx_primary),
        simplex_resolver: (resolver_primary, resolver_rx_primary),
        backfill: (backfill_primary, backfill_rx_primary),
        broadcast: (broadcast_primary, broadcast_rx_primary),
        database: (raw.database.0.clone(), database_rx_primary),
    };
    let secondary_channels = EngineChannels {
        vote: (vote_secondary, vote_rx_secondary),
        certificate: (certificate_secondary, certificate_rx_secondary),
        simplex_resolver: (resolver_secondary, resolver_rx_secondary),
        backfill: (backfill_secondary, backfill_rx_secondary),
        broadcast: (broadcast_secondary, broadcast_rx_secondary),
        database: (raw.database.0, database_rx_secondary),
    };

    let _primary = spawn_engine(
        node_context.child("primary"),
        oracle.clone(),
        EngineConfig {
            identity: identity.clone(),
            scheme: scheme.clone(),
            elector: elector.clone(),
            genesis: genesis.clone(),
            partition_prefix: format!("engine-{compromised}-primary"),
            application: CorrectApp::new(genesis.clone(), observations[compromised].clone()),
            observations: observations[compromised].clone(),
        },
        primary_channels,
    );

    let mut fault_rng = FuzzRng::new(entropy.clone());
    let schedule = FaultSchedule::new(&mut fault_rng, input.faults);
    let _secondary = spawn_engine(
        node_context.child("secondary"),
        oracle.clone(),
        EngineConfig {
            identity,
            scheme,
            elector: elector.clone(),
            genesis: genesis.clone(),
            partition_prefix: format!("engine-{compromised}-secondary"),
            application: FaultyApp::new(
                CorrectApp::new(genesis.clone(), observations[SECONDARY_ENGINE].clone()),
                schedule,
            ),
            observations: observations[SECONDARY_ENGINE].clone(),
        },
        secondary_channels,
    );

    // Restart schedule. Only correct identities are crashed, and the scheduler
    // runs them one at a time, so at most one correct identity is ever down.
    let mut restart_rng = FuzzRng::new(entropy);
    let mut events = Vec::with_capacity(usize::from(input.restarts));
    for _ in 0..input.restarts {
        let mut sample = [0u8; 2];
        restart_rng.fill(&mut sample[..]);
        events.push((
            Duration::from_millis(50 + u64::from(sample[0] % 16) * 50),
            usize::from(sample[1]) % correct.len(),
        ));
    }

    let prefix_end = View::new(PREFIX_ROUNDS as u64 * term_length.get());
    // One waiter per correct node, subscribed before the run advances so no
    // applied height is missed. A waiter completes once its node has applied
    // the required number of distinct heights past the adversarial prefix.
    // Completion is keyed on application rather than delivery: the commitment
    // I2 compares is recorded after the batch is applied, so waiting on
    // delivery could end the run with the last block still queued.
    let required = usize::from(input.required_heights);
    let waiters: Vec<_> = correct
        .iter()
        .map(|node| {
            let mut applied = node.observations.subscribe_applied();
            context
                .child("waiter")
                .with_attribute("index", node.engine)
                .spawn(move |_| async move {
                    let mut heights = BTreeSet::new();
                    while heights.len() < required {
                        match applied.recv().await {
                            Some((height, view)) => {
                                if view > prefix_end {
                                    heights.insert(height);
                                }
                            }
                            None => std::future::pending().await,
                        }
                    }
                })
        })
        .collect();

    // Run the scripted restarts, then wait for every correct node to apply its
    // required suffix heights. The whole sequence is bounded by the run timeout,
    // so a cluster that stalls simply stops here rather than failing.
    let outcome = {
        let run = async {
            for (delay, victim) in events {
                context.sleep(delay).await;
                let node = &mut correct[victim];
                node.handle.abort();
                context.sleep(RESTART_DOWNTIME).await;
                node.handle = start_correct(
                    &context,
                    &oracle,
                    node.engine,
                    node.identity.clone(),
                    node.scheme.clone(),
                    &elector,
                    &genesis,
                    node.partition.clone(),
                    node.observations.clone(),
                )
                .await;
                node.observations.note_restart();
            }
            join_all(waiters).await;
        };
        select! {
            _ = context.sleep(RUN_TIMEOUT) => Outcome::Timeout,
            _ = run => Outcome::Suffix,
        }
    };

    // Measurement point. Both halves of the compromised identity are excluded.
    let correct_nodes: Vec<(usize, &EngineObservations)> = correct
        .iter()
        .map(|node| (node.engine, &node.observations))
        .collect();
    let counts = Counts {
        correct_nodes: correct_nodes.len(),
        chain_heights: invariants::check_chain_of_blocks(&correct_nodes, genesis_digest),
        state_comparisons: invariants::check_state_agreement(&correct_nodes),
        verdict_comparisons: invariants::check_verdict_agreement(&correct_nodes),
        restarts: observations.iter().map(EngineObservations::restarts).sum(),
    };
    RunReport { outcome, counts }
}

/// Start (or restart) one correct identity's engine.
///
/// A restart reuses the identity's key, its channel registrations, and its
/// storage partitions, so the rebuilt engine reconciles its database set
/// against marshal's processed anchor and comes back with an empty pending map.
#[allow(clippy::too_many_arguments)]
async fn start_correct(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKey, deterministic::Context>,
    engine: usize,
    identity: PublicKey,
    scheme: Scheme,
    elector: &Elector,
    genesis: &Block,
    partition: String,
    observations: EngineObservations,
) -> Handle<()> {
    let channels = register_channels(oracle, &identity).await.whole();
    spawn_engine(
        context.child("correct").with_attribute("index", engine),
        oracle.clone(),
        EngineConfig {
            identity,
            scheme,
            elector: elector.clone(),
            genesis: genesis.clone(),
            partition_prefix: partition,
            application: CorrectApp::new(genesis.clone(), observations.clone()),
            observations,
        },
        channels,
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

    #[allow(clippy::too_many_arguments)]
    fn input(
        case_selector: u16,
        sustained: bool,
        faults: FaultArming,
        required_heights: u8,
        term_length: u32,
        restarts: u8,
        seed: u8,
    ) -> StatefulTwinsFuzzInput {
        StatefulTwinsFuzzInput {
            case_selector,
            sustained,
            faults,
            required_heights,
            term_length: TermLength::new(NZU32!(term_length)),
            restarts,
            raw_bytes: tape(seed),
        }
    }

    /// Runs one fixed input and asserts the checks were not vacuous.
    fn measured(input: StatefulTwinsFuzzInput) -> RunReport {
        let report = run_stateful_twins(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run measured nothing and must not be counted as passing: {report}"
        );
        report
    }

    #[test]
    fn sampled_partitions_hold_invariants() {
        measured(input(0, false, ALL_FAULTS, 1, 1, 0, 0));
    }

    #[test]
    fn sustained_partitions_hold_invariants() {
        measured(input(0, true, ALL_FAULTS, 2, 1, 0, 0));
    }

    #[test]
    fn disarmed_adversary_holds_invariants() {
        measured(input(0, false, NO_FAULTS, 1, 1, 0, 0));
    }

    #[test]
    fn restarts_exercise_lazy_recovery() {
        let report = measured(input(0, false, ALL_FAULTS, 3, 1, 2, 0));
        assert!(
            report.counts.restarts > 0,
            "restart schedule executed nothing: {report}"
        );
    }

    #[test]
    fn restarts_under_sustained_partitions_hold_invariants() {
        let report = measured(input(3, true, ALL_FAULTS, 2, 2, 3, 7));
        assert!(
            report.counts.restarts > 0,
            "restart schedule executed nothing: {report}"
        );
    }

    /// The target explores a scenario per case selector; every one of them is a
    /// regression case.
    #[test]
    fn selected_cases_hold_invariants() {
        for case_selector in 0..8 {
            let report = run_stateful_twins(input(
                case_selector,
                case_selector % 2 == 1,
                ALL_FAULTS,
                u8::try_from(case_selector % MAX_REQUIRED_HEIGHTS as u16).expect("fits") + 1,
                u32::from(case_selector % MAX_TERM_LENGTH as u16) + 1,
                u8::try_from(case_selector % 3).expect("fits"),
                u8::try_from(case_selector).expect("fits"),
            ));
            println!("case {case_selector}: {report}");
            assert!(
                report.counts.correct_nodes > 0,
                "case {case_selector} observed no correct node: {report}"
            );
        }
    }

    /// I6: a replayed input fails, or passes, identically.
    #[test]
    fn replay_is_reproducible() {
        let first = run_stateful_twins(input(2, false, ALL_FAULTS, 2, 3, 1, 11));
        let second = run_stateful_twins(input(2, false, ALL_FAULTS, 2, 3, 1, 11));
        assert_eq!(first, second, "replaying an input changed what it measured");
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(0, false, ALL_FAULTS, 1, 1, 0, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}

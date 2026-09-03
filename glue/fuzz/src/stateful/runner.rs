//! Machinery shared by the two drivers: cluster setup, correct-node startup and
//! restart, the measurement point, and the run report.
//!
//! A run ends when every correct node has applied the required number of
//! heights past the adversarial prefix, or when its bounded timeout expires.
//! Completion is keyed on application rather than on delivery, because the
//! database commitment I2 compares is written only once the batch is applied.
//! Progress is never asserted: a cluster that stalls simply stops at the
//! timeout, and the invariants are then checked over whatever was observed,
//! including nothing.

use super::{
    Databases, NAMESPACE, NUM_IDENTITIES, PublicKey, RESTART_DOWNTIME, Scheme,
    app::{Block, CorrectApp},
    invariants::{self, Counts, EngineObservations},
    stack::{ElectorConfig, EngineConfig, register_channels, spawn_engine},
};
use commonware_consensus::types::View;
use commonware_cryptography::Digestible;
use commonware_glue::stateful::db::DatabaseSet;
use commonware_p2p::simulated::{
    Config as NetworkConfig, Link, Network as SimulatedNetwork, Oracle,
};
use commonware_runtime::{Handle, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{
    FuzzRng, NZUsize, probability,
    sync::{Mutex, Once},
};
use rand::RngExt as _;
use std::{collections::BTreeSet, fmt, panic, sync::Arc, time::Duration};

/// Environment variable enabling the per-run report.
const REPORT_ENV: &str = "GLUE_FUZZ_LOG";

/// Every directed link stays up for the whole run. A driver that partitions the
/// network does so by splitting channels, never by manipulating links.
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

/// Why a run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every correct node applied its required heights past the scripted views.
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
    /// The driver that produced this run.
    pub target: &'static str,
    /// Why the run stopped.
    pub outcome: Outcome,
    /// How much each check compared.
    pub counts: Counts,
}

impl RunReport {
    pub(super) const fn skipped(target: &'static str, outcome: Outcome) -> Self {
        Self {
            target,
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
            "[{}] outcome={} correct_nodes={} chain_heights={} state_comparisons={} \
             verdict_comparisons={} restarts={}{}",
            self.target,
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

/// Announce the run in flight and report the result the way a fuzz target does.
pub(super) fn report(raw_bytes: &[u8], run: impl FnOnce() -> RunReport) {
    install_input_panic_hook();
    IN_FLIGHT.lock().clear();
    IN_FLIGHT.lock().extend_from_slice(raw_bytes);
    let report = run();

    // A run that measured nothing is always reported, so it is never silently
    // counted as a run that found nothing.
    if !report.measured() || std::env::var_os(REPORT_ENV).is_some() {
        eprintln!("{report}");
    }
}

/// The identities, network, and genesis block every driver starts from.
pub(super) struct Cluster {
    pub(super) participants: Arc<[PublicKey]>,
    pub(super) schemes: Vec<Scheme>,
    pub(super) oracle: Oracle<PublicKey, deterministic::Context>,
    pub(super) genesis: Block,
}

/// Derive the identities and their mock schemes, start the simulated network
/// with every directed link up, and build the shared genesis block.
pub(super) async fn setup(context: &mut deterministic::Context) -> Cluster {
    let fixture = commonware_consensus::simplex::mocks::scheme::fixture_with::<false, true, true, _>(
        context,
        NAMESPACE,
        NUM_IDENTITIES,
    );
    let participants: Arc<[PublicKey]> = fixture.participants.clone().into();

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

    // Every engine starts from the same block with no finalized floor.
    let initial = <Databases as DatabaseSet<deterministic::Context>>::initial_sync_targets();
    let genesis = Block::genesis(participants[0].clone(), initial.root, initial.range);
    Cluster {
        participants,
        schemes: fixture.schemes,
        oracle,
        genesis,
    }
}

/// One correct identity's engine, retained so a restart can rebuild it on the
/// same storage partitions under the same key.
pub(super) struct CorrectEngine<EC> {
    pub(super) engine: usize,
    identity: PublicKey,
    scheme: Scheme,
    elector: EC,
    partition: String,
    pub(super) observations: EngineObservations,
    handle: Handle<()>,
}

impl<EC: ElectorConfig> CorrectEngine<EC> {
    /// Start one correct identity's engine.
    pub(super) async fn start(
        context: &deterministic::Context,
        cluster: &Cluster,
        engine: usize,
        elector: EC,
        observations: EngineObservations,
    ) -> Self {
        let identity = cluster.participants[engine].clone();
        let scheme = cluster.schemes[engine].clone();
        let partition = format!("engine-{engine}");
        let handle = spawn(
            context,
            cluster,
            engine,
            &identity,
            &scheme,
            &elector,
            &partition,
            &observations,
        )
        .await;
        Self {
            engine,
            identity,
            scheme,
            elector,
            partition,
            observations,
            handle,
        }
    }

    /// Crash this engine and bring it back on its retained storage.
    ///
    /// A restart reuses the identity's key, its channel registrations, and its
    /// storage partitions, so the rebuilt engine reconciles its database set
    /// against marshal's processed anchor and comes back with an empty pending
    /// map, forcing lazy recovery on its next proposal or verification.
    pub(super) async fn restart(
        &mut self,
        context: &deterministic::Context,
        cluster: &Cluster,
        downtime: Duration,
    ) {
        self.handle.abort();
        commonware_runtime::Clock::sleep(context, downtime).await;
        self.handle = spawn(
            context,
            cluster,
            self.engine,
            &self.identity,
            &self.scheme,
            &self.elector,
            &self.partition,
            &self.observations,
        )
        .await;
        self.observations.note_restart();
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn<EC: ElectorConfig>(
    context: &deterministic::Context,
    cluster: &Cluster,
    engine: usize,
    identity: &PublicKey,
    scheme: &Scheme,
    elector: &EC,
    partition: &str,
    observations: &EngineObservations,
) -> Handle<()> {
    let channels = register_channels(&cluster.oracle, identity).await.whole();
    spawn_engine(
        context.child("correct").with_attribute("index", engine),
        cluster.oracle.clone(),
        EngineConfig {
            identity: identity.clone(),
            scheme: scheme.clone(),
            elector: elector.clone(),
            genesis: cluster.genesis.clone(),
            partition_prefix: partition.to_string(),
            application: CorrectApp::new(cluster.genesis.clone(), observations.clone()),
            observations: observations.clone(),
        },
        channels,
    )
}

/// Draw a restart schedule from the tape.
///
/// The events are executed one at a time by a single task, which is what
/// enforces that at most one correct identity is ever down.
pub(super) fn restart_schedule(
    rng: &mut FuzzRng,
    count: u8,
    nodes: usize,
) -> Vec<(Duration, usize)> {
    (0..count)
        .map(|_| {
            let mut sample = [0u8; 2];
            rng.fill(&mut sample[..]);
            (
                Duration::from_millis(50 + u64::from(sample[0] % 16) * 50),
                usize::from(sample[1]) % nodes,
            )
        })
        .collect()
}

/// One waiter per correct node, each completing once its node has applied the
/// required number of distinct heights in views after `scripted_through`.
///
/// `scripted_through` is the last view a driver scripts. Heights applied at or
/// before it do not count, which is what stops a run from finishing before its
/// scripted program has been played out: a driver that scripts three rounds
/// would otherwise be free to satisfy a one-height requirement in the first
/// view and never reach the second or third. A driver that scripts nothing
/// passes `View::zero()`, and then every applied height counts.
pub(super) fn waiters<EC>(
    context: &deterministic::Context,
    nodes: &[CorrectEngine<EC>],
    required: usize,
    scripted_through: View,
) -> Vec<Handle<()>> {
    nodes
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
                                if view > scripted_through {
                                    heights.insert(height);
                                }
                            }
                            None => std::future::pending().await,
                        }
                    }
                })
        })
        .collect()
}

/// Check the invariants over the correct nodes and report what was compared.
pub(super) fn measure<EC>(
    target: &'static str,
    outcome: Outcome,
    nodes: &[CorrectEngine<EC>],
    observations: &[EngineObservations],
    genesis: &Block,
) -> RunReport {
    let correct: Vec<(usize, &EngineObservations)> = nodes
        .iter()
        .map(|node| (node.engine, &node.observations))
        .collect();
    let counts = Counts {
        correct_nodes: correct.len(),
        chain_heights: invariants::check_chain_of_blocks(&correct, genesis.digest()),
        state_comparisons: invariants::check_state_agreement(&correct),
        verdict_comparisons: invariants::check_verdict_agreement(&correct),
        restarts: observations.iter().map(EngineObservations::restarts).sum(),
    };
    RunReport {
        target,
        outcome,
        counts,
    }
}

/// The downtime a scheduled restart waits between abort and rejoin.
pub(super) const fn downtime() -> Duration {
    RESTART_DOWNTIME
}

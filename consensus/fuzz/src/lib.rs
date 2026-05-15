pub mod bounds;
pub mod byzzfuzz;
#[cfg(feature = "mocks")]
pub mod certificate_mock;
pub mod disrupter;
pub mod id_mock;
pub mod invariants;
pub mod network;
pub mod simplex;
pub mod simplex_node;
pub mod strategy;
pub mod types;
pub mod utils;
use crate::{
    disrupter::Disrupter,
    network::ByzantineFirstReceiver,
    simplex_node::NodeFuzzInput,
    strategy::{AnyScope, FutureScope, SmallScope, Strategy, StrategyChoice},
    utils::{apply_partition, link_peers, register, Action, Partition, SetPartition},
};
use arbitrary::Arbitrary;
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_consensus::{
    simplex::{
        config,
        elector::Config as ElectorConfig,
        mocks::{application, relay, reporter, twins},
        types::{Certificate, Vote},
        Engine, ForwardingPolicy,
    },
    types::{Delta, Epoch, View},
    Monitor, Viewable,
};
use commonware_cryptography::{
    certificate::Scheme, sha256::Digest as Sha256Digest, PublicKey as CryptoPublicKey, Sha256,
};
use commonware_p2p::{
    simulated::{Config as NetworkConfig, Link, Network, Oracle, SplitOrigin, SplitTarget},
    Recipients,
};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Clock, IoBuf, Runner, Spawner, Supervisor as _,
};
use commonware_utils::{
    channel::mpsc::{self, Receiver},
    sequence::U64,
    sync::Once,
    FuzzRng, NZUsize, NZU16,
};
use futures::future::join_all;
#[cfg(feature = "mocks")]
pub use simplex::SimplexCertificateMock;
pub use simplex::{
    SimplexBls12381MinPk, SimplexBls12381MinPkCustomRandom, SimplexBls12381MinSig,
    SimplexBls12381MultisigMinPk, SimplexBls12381MultisigMinSig, SimplexEd25519,
    SimplexEd25519CustomRoundRobin, SimplexId, SimplexSecp256r1,
};
use std::{
    collections::HashMap,
    fmt,
    num::{NonZeroU16, NonZeroUsize},
    panic,
    sync::Arc,
    time::Duration,
};
pub const EPOCH: u64 = 333;

const FUZZ_LOG_ENV: &str = "CONSENSUS_FUZZ_LOG";

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
pub(crate) const FAULT_INJECTION_RATIO: u64 = 5;
const MIN_NUMBER_OF_FAULTS: u64 = 2;
const MIN_REQUIRED_CONTAINERS: u64 = 1;
const MAX_REQUIRED_CONTAINERS: u64 = 30;
/// Per-view honest-message drop rate range used by `Mode::FaultyMessaging`.
/// Bounded conservatively so finalization remains reachable across the run -
/// `FaultyMessaging` waits for finalization (`Partition::Connected` is enforced),
/// and unbounded loss would let pathological schedules hang the deterministic
/// runtime. Increase only if a complementary timeout is added to the wait loop.
pub(crate) const MIN_HONEST_MESSAGES_DROP_RATIO: u8 = 0;
pub(crate) const MAX_HONEST_MESSAGES_DROP_RATIO: u8 = 5;
pub(crate) const MAX_SLEEP_DURATION: Duration = Duration::from_secs(5);
const NAMESPACE: &[u8] = b"consensus_fuzz";
const MAX_RAW_BYTES: usize = 32_768;

/// Network configuration for fuzz testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Configuration {
    /// Total number of nodes.
    pub n: u32,
    /// Number of faulty (Byzantine) nodes.
    pub faults: u32,
    /// Number of correct (honest) nodes.
    pub correct: u32,
}

impl Configuration {
    pub const fn new(n: u32, faults: u32, correct: u32) -> Self {
        Self { n, faults, correct }
    }

    /// Returns true if this configuration is valid:
    /// number of faulty and correct nodes satisfy the protocol fault tolerance constraints.
    /// A valid configuration is required for the protocol to make progress in periods of synchrony (liveness).
    pub fn is_valid(&self) -> bool {
        self.faults <= bounds::max_faults(self.n) && self.n == self.faults + self.correct
    }
}

/// 4 nodes, 1 faulty, 3 correct (standard BFT config)
pub const N4F1C3: Configuration = Configuration::new(4, 1, 3);
/// 4 nodes, 3 faulty, 1 correct (adversarial majority, no liveness)
pub const N4F3C1: Configuration = Configuration::new(4, 3, 1);
/// 4 nodes, 0 faulty, 4 correct (all nodes are correct)
pub const N4F0C4: Configuration = Configuration::new(4, 0, 4);

async fn setup_degraded_network<P: CryptoPublicKey, E: Clock>(
    oracle: &mut Oracle<P, E>,
    participants: &[P],
) {
    let Some(victim) = participants.last() else {
        return;
    };
    let victim_idx = participants.len() - 1;
    let degraded = Link {
        latency: Duration::from_millis(50),
        jitter: Duration::from_millis(50),
        success_rate: 0.6,
    };
    for (peer_idx, peer) in participants.iter().enumerate() {
        if peer_idx == victim_idx {
            continue;
        }
        oracle.remove_link(victim.clone(), peer.clone()).await.ok();
        oracle.remove_link(peer.clone(), victim.clone()).await.ok();
        oracle
            .add_link(victim.clone(), peer.clone(), degraded.clone())
            .await
            .unwrap();
        oracle
            .add_link(peer.clone(), victim.clone(), degraded.clone())
            .await
            .unwrap();
    }
}

/// Per-iteration choice of `Application::certify` behavior.
///
/// `SingleCancel` and `SinglePending` apply their non-default certifier only
/// to the validator at `target_idx` so quorum certification is still reachable
/// when the selected validator already overlaps another modeled adversary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifyChoice {
    Always,
    SingleCancel { target_idx: u8 },
    SinglePending { target_idx: u8 },
}

impl CertifyChoice {
    pub fn into_certifier(self, validator_idx: usize) -> application::Certifier<Sha256Digest> {
        match self {
            CertifyChoice::Always => application::Certifier::Always,
            CertifyChoice::SingleCancel { target_idx } => {
                if validator_idx == target_idx as usize {
                    application::Certifier::Cancel
                } else {
                    application::Certifier::Always
                }
            }
            CertifyChoice::SinglePending { target_idx } => {
                if validator_idx == target_idx as usize {
                    application::Certifier::Pending
                } else {
                    application::Certifier::Always
                }
            }
        }
    }
}

struct FuzzInputDebug<'a>(&'a FuzzInput);

impl fmt::Debug for FuzzInputDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input = self.0;
        f.debug_struct("FuzzInput")
            .field("raw_bytes_len", &input.raw_bytes.len())
            .field("required_containers", &input.required_containers)
            .field("degraded_network", &input.degraded_network)
            .field("configuration", &input.configuration)
            .field("partition", &input.partition)
            .field("strategy", &input.strategy)
            .field("messaging_faults", &input.messaging_faults)
            .field("forwarding", &input.forwarding)
            .field("certify", &input.certify)
            .finish()
    }
}

struct NodeFuzzInputDebug<'a>(&'a NodeFuzzInput);

impl fmt::Debug for NodeFuzzInputDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input = self.0;
        f.debug_struct("NodeFuzzInput")
            .field("raw_bytes_len", &input.raw_bytes.len())
            .field("events", &input.events)
            .field("forwarding", &input.forwarding)
            .field("certify", &input.certify)
            .finish()
    }
}

fn print_fuzz_input(mode: Mode, input: &FuzzInput) {
    if std::env::var_os(FUZZ_LOG_ENV).is_some() {
        eprintln!(
            "consensus fuzz configuration: mode={mode:?} input={:?}",
            FuzzInputDebug(input)
        );
    }
}

fn print_node_fuzz_input(mode: simplex_node::NodeMode, input: &NodeFuzzInput) {
    if std::env::var_os(FUZZ_LOG_ENV).is_some() {
        eprintln!(
            "consensus node fuzz configuration: mode={mode:?} input={:?}",
            NodeFuzzInputDebug(input)
        );
    }
}

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub degraded_network: bool,
    pub configuration: Configuration,
    pub partition: Partition,
    pub strategy: StrategyChoice,
    /// Round-indexed schedule of honest-message drop rates, used only by
    /// `Mode::FaultyMessaging`. Each entry `(view, rate)` activates an
    /// `rate%` honest-message drop while the reference reporter is in `view`;
    /// the rate reverts to 0 outside scheduled views.
    pub messaging_faults: Vec<(View, u8)>,
    /// Per-iteration forwarding policy threaded into every engine the harness
    /// spawns. Sampling lets the fuzzer drive coverage of all three arms of
    /// `batcher::forward_targets` instead of pinning to `Disabled`.
    pub forwarding: ForwardingPolicy,
    /// Per-iteration certify policy threaded into every honest validator
    /// the harness spawns.
    pub certify: CertifyChoice,
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Partition distribution:
        //   30%  fully Connected (no fault)
        //   20%  Static fault: uniform sample over the 14 non-trivial set
        //        partitions of {0,1,2,3} (Bell(4) - 1 = 14; the trivial single-block
        //        partition is excluded since it equals `Connected`)
        //   50%  Adaptive (round-indexed schedule, populated later)
        let partition = match u.int_in_range(0..=99)? {
            0..=29 => Partition::Connected,
            30..=49 => {
                // 14 non-trivial partitions live at N4[1..15].
                let idx = u.int_in_range(1..=14)?;
                Partition::Static(SetPartition::n4(idx))
            }
            _ => Partition::Adaptive(Vec::new()),
        };

        let configuration = match u.int_in_range(1..=100)? {
            1..=95 => N4F1C3, // 95%
            _ => N4F0C4,      // 5%
        };

        // Bias degraded networking - 1%
        let degraded_network = partition == Partition::Connected
            && configuration == N4F1C3
            && u.int_in_range(0..=99)? == 1;

        let required_containers =
            u.int_in_range(MIN_REQUIRED_CONTAINERS..=MAX_REQUIRED_CONTAINERS)?;

        // SmallScope mutations with round-based injections - 80%,
        // AnyScope mutations - 10%,
        // FutureScope mutations with round-based injections - 10%
        let fault_rounds_bound = u.int_in_range(1..=required_containers)?;
        let min_fault_rounds = MIN_NUMBER_OF_FAULTS.min(fault_rounds_bound);
        let max_fault_rounds = (fault_rounds_bound / FAULT_INJECTION_RATIO).max(min_fault_rounds);
        let fault_rounds = u.int_in_range(min_fault_rounds..=max_fault_rounds)?;
        let strategy = match u.int_in_range(0..=9)? {
            0 => StrategyChoice::AnyScope,
            1 => StrategyChoice::FutureScope {
                fault_rounds,
                fault_rounds_bound,
            },
            _ => StrategyChoice::SmallScope {
                fault_rounds,
                fault_rounds_bound,
            },
        };

        // Forwarding policy distribution:
        //   33%  Disabled       - matches prior fuzz behavior; covers the no-op path
        //   33%  SilentVoters   - exercises `forward_targets` -> `missing_voters`
        //   34%  SilentLeader   - exercises `forward_targets` -> leader-only branch
        let forwarding = match u.int_in_range(0..=2)? {
            0 => ForwardingPolicy::Disabled,
            1 => ForwardingPolicy::SilentVoters,
            _ => ForwardingPolicy::SilentLeader,
        };

        // Single-target certify variants are not sampled here because standard
        // N4F1C3 modes have only three honest certifiers; disabling one drops
        // below the quorum of three.
        let certify = CertifyChoice::Always;

        // Collect bytes for RNG
        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = u.bytes(remaining)?.to_vec();

        // The messaging-fault schedule (for `Mode::FaultyMessaging`) is generated
        // at runtime by `Strategy::messaging_faults` from the deterministic
        // FuzzRng, mirroring the `Adaptive` partition path - keeps schedule
        // density tied to the chosen byzantine strategy.
        Ok(Self {
            raw_bytes,
            partition,
            configuration,
            degraded_network,
            required_containers,
            strategy,
            messaging_faults: Vec::new(),
            forwarding,
            certify,
        })
    }
}

pub(crate) type PublicKeyOf<P> = <<P as simplex::Simplex>::Scheme as Scheme>::PublicKey;

type ReporterOf<P> = reporter::Reporter<
    deterministic::Context,
    <P as simplex::Simplex>::Scheme,
    <P as simplex::Simplex>::Elector,
    Sha256Digest,
>;

type ReporterEntry<P> = (PublicKeyOf<P>, ReporterOf<P>);

type NetworkChannels<P> = (
    (
        commonware_p2p::simulated::Sender<P, deterministic::Context>,
        commonware_p2p::simulated::Receiver<P>,
    ),
    (
        commonware_p2p::simulated::Sender<P, deterministic::Context>,
        commonware_p2p::simulated::Receiver<P>,
    ),
    (
        commonware_p2p::simulated::Sender<P, deterministic::Context>,
        commonware_p2p::simulated::Receiver<P>,
    ),
);

/// Common setup for fuzz tests: network, participants, links.
pub(crate) async fn setup_network<P: simplex::Simplex>(
    context: &mut deterministic::Context,
    input: &FuzzInput,
) -> (
    Oracle<PublicKeyOf<P>, deterministic::Context>,
    Vec<PublicKeyOf<P>>,
    Vec<P::Scheme>,
    HashMap<PublicKeyOf<P>, NetworkChannels<PublicKeyOf<P>>>,
) {
    let (participants, schemes) = P::setup(context, NAMESPACE, input.configuration.n);
    let (network, mut oracle) = Network::new_with_peers(
        context.child("network"),
        NetworkConfig {
            max_size: 1024 * 1024,
            disconnect_on_block: false,
            tracked_peer_sets: NZUsize!(1),
        },
        participants.clone(),
    )
    .await;
    network.start();

    let registrations = register(&mut oracle, &participants).await;

    let link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };
    link_peers(
        &mut oracle,
        &participants,
        Action::Link(link),
        input.partition.set_partition(),
    )
    .await;

    if input.partition == Partition::Connected
        && input.configuration == N4F1C3
        && input.degraded_network
    {
        setup_degraded_network(&mut oracle, &participants).await;
    }

    (oracle, participants, schemes, registrations)
}

/// Start a Disrupter with the given strategy and network channels.
fn start_disrupter<P: simplex::Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    strategy: &StrategyChoice,
    required_containers: u64,
    vote_network: (
        impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate_network: (
        impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver_network: (
        impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
        impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ),
) {
    match *strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new(
                context,
                scheme,
                SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::AnyScope => {
            let disrupter = Disrupter::new(context, scheme, AnyScope, required_containers);
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new(
                context,
                scheme,
                FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
    }
}

/// Spawn a Disrupter for a Byzantine node.
fn spawn_disrupter<P: simplex::Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    input: &FuzzInput,
    channels: NetworkChannels<PublicKeyOf<P>>,
) {
    let (vote_network, certificate_network, resolver_network) = channels;
    start_disrupter::<P>(
        context.child("disrupter"),
        scheme,
        &input.strategy,
        input.required_containers,
        vote_network,
        certificate_network,
        resolver_network,
    );
}

/// Spawn an honest validator with application, reporter, and engine.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_honest_validator<
    P,
    EC,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: EC,
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    forwarding: ForwardingPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
) -> reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme> + Clone + Send + 'static,
    PendingSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    PendingReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    RecoveredSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    RecoveredReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ResolverSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    ResolverReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    let reporter_cfg = reporter::Config {
        participants: participants.try_into().expect("public keys are unique"),
        scheme: scheme.clone(),
        elector: elector.clone(),
    };
    let reporter = reporter::Reporter::new(context.child("reporter"), reporter_cfg);

    let (vote_sender, vote_receiver) = pending;
    let (certificate_sender, certificate_receiver) = recovered;
    let (resolver_sender, resolver_receiver) = resolver;

    let validator_idx = participants
        .iter()
        .position(|p| p == &validator)
        .expect("validator must be in participants");
    let app_cfg = application::Config {
        hasher: Sha256::default(),
        relay,
        me: validator.clone(),
        propose_latency: (10.0, 5.0),
        verify_latency: (10.0, 5.0),
        certify_latency: (10.0, 5.0),
        should_certify: certify.into_certifier(validator_idx),
    };
    let (actor, application) = application::Application::new(context.child("application"), app_cfg);
    actor.start();

    let blocker = oracle.control(validator.clone());
    let engine_cfg = config::Config {
        blocker,
        scheme,
        elector,
        automaton: application.clone(),
        relay: application.clone(),
        reporter: reporter.clone(),
        partition: validator.to_string(),
        mailbox_size: NZUsize!(1024),
        epoch: Epoch::new(EPOCH),
        leader_timeout,
        certification_timeout,
        timeout_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        activity_timeout: Delta::new(10),
        skip_timeout: Delta::new(5),
        fetch_concurrent: NZUsize!(1),
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
        forwarding,
    };
    let engine = Engine::new(context.child("engine"), engine_cfg);
    engine.start(
        (vote_sender, vote_receiver),
        (certificate_sender, certificate_receiver),
        (resolver_sender, resolver_receiver),
    );

    reporter
}

#[allow(clippy::too_many_arguments)]
fn spawn_honest_validator_in_faulty_messaging<P: simplex::Simplex>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    byzantine_router: crate::network::Router<PublicKeyOf<P>, deterministic::Context>,
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    forwarding: ForwardingPolicy,
    channels: NetworkChannels<PublicKeyOf<P>>,
    certify: CertifyChoice,
) -> reporter::Reporter<deterministic::Context, P::Scheme, P::Elector, Sha256Digest> {
    let (vote_network, certificate_network, resolver_network) = channels;
    let (vote_sender, vote_receiver) = vote_network;
    let (certificate_sender, certificate_receiver) = certificate_network;
    let (resolver_sender, resolver_receiver) = resolver_network;

    let vote_router = byzantine_router.clone();
    let (vote_primary, vote_secondary) = vote_receiver
        .split_with(context.child("byzantine_first_vote"), move |msg| {
            vote_router.route(msg)
        });
    let vote_receiver = ByzantineFirstReceiver::new(vote_primary, vote_secondary);

    let certificate_router = byzantine_router.clone();
    let (certificate_primary, certificate_secondary) = certificate_receiver
        .split_with(context.child("byzantine_first_certificate"), move |msg| {
            certificate_router.route(msg)
        });
    let certificate_receiver =
        ByzantineFirstReceiver::new(certificate_primary, certificate_secondary);

    let resolver_router = byzantine_router;
    let (resolver_primary, resolver_secondary) = resolver_receiver
        .split_with(context.child("byzantine_first_resolver"), move |msg| {
            resolver_router.route(msg)
        });
    let resolver_receiver = ByzantineFirstReceiver::new(resolver_primary, resolver_secondary);

    spawn_honest_validator::<P, _, _, _, _, _, _, _>(
        context,
        oracle,
        participants,
        scheme,
        validator,
        P::Elector::default(),
        relay,
        leader_timeout,
        certification_timeout,
        forwarding,
        (vote_sender, vote_receiver),
        (certificate_sender, certificate_receiver),
        (resolver_sender, resolver_receiver),
        certify,
    )
}

/// Default link used by the round-indexed fault scheduler when re-establishing edges.
fn default_link() -> Link {
    Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    }
}

fn scheduled_partition(
    schedule: &[(View, SetPartition)],
    executing_view: u64,
) -> Option<SetPartition> {
    schedule
        .iter()
        .find_map(|(view, p)| (*view == View::new(executing_view)).then_some(*p))
}

/// Look up the partition scheduled for view 1, the initial executing view.
/// The caller applies this synchronously before validators run so early view-1
/// traffic observes the scheduled topology.
fn initial_network_partition(partition: &Partition) -> Option<SetPartition> {
    partition
        .schedule()
        .and_then(|schedule| scheduled_partition(schedule, 1))
}

async fn reporter_view_stream<P: simplex::Simplex>(
    context: &deterministic::Context,
    reporters: &mut [ReporterEntry<P>],
) -> Option<(u64, mpsc::UnboundedReceiver<u64>)> {
    if reporters.is_empty() {
        return None;
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let mut max_finalized_view = 0;
    for (idx, (_, reporter)) in reporters.iter_mut().enumerate() {
        let (latest, mut monitor) = reporter.subscribe().await;
        max_finalized_view = max_finalized_view.max(latest.get());
        let tx = tx.clone();
        context
            .child("reporter_view_watcher")
            .with_attribute("index", idx)
            .spawn(move |_| async move {
                while let Some(next) = monitor.recv().await {
                    if tx.send(next.get()).is_err() {
                        break;
                    }
                }
            });
    }
    drop(tx);
    Some((max_finalized_view, rx))
}

async fn spawn_network_fault_scheduler<P: simplex::Simplex>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    reporters: &mut [ReporterEntry<P>],
    partition: Partition,
    required_containers: u64,
    initial_partition: Option<SetPartition>,
) {
    let Some(schedule) = partition.schedule() else {
        return;
    };
    if schedule.is_empty() || reporters.is_empty() {
        return;
    }
    let Some((mut finalized_view, mut view_rx)) =
        reporter_view_stream::<P>(context, reporters).await
    else {
        return;
    };
    let oracle = oracle.clone();
    let participants: Vec<_> = participants.to_vec();
    let schedule = schedule.to_vec();
    context
        .child("network_fault_scheduler")
        .spawn(move |_| async move {
            let link = default_link();
            let mut active = initial_partition;
            loop {
                let executing_view = finalized_view.saturating_add(1);
                let target = scheduled_partition(&schedule, executing_view);
                if target != active {
                    apply_partition(&oracle, &participants, target.as_ref(), &link).await;
                    active = target;
                }
                if executing_view > required_containers {
                    break;
                }
                let Some(next) = view_rx.recv().await else {
                    break;
                };
                finalized_view = finalized_view.max(next);
            }
        });
}

/// Look up the rate scheduled for view 1 (the initial executing view), or `0`
/// if no entry matches. Used to seed the drop-rate cell synchronously *before*
/// validators run, so that very early view-1 traffic sees the scheduled rate.
fn initial_drop_rate(schedule: &[(View, u8)]) -> u8 {
    schedule
        .iter()
        .find_map(|(view, rate)| (*view == View::new(1)).then_some(*rate))
        .unwrap_or(0)
}

/// Drives the per-view honest-message drop rate for `Mode::FaultyMessaging`.
/// Subscribes to the first reporter's view monitor and updates the shared
/// [`network::DropRateCell`] when the active *executing* view's scheduled rate
/// differs from the current one. No-op when the schedule is empty or no
/// reporters were spawned.
///
/// `initial_rate` must equal the value the caller already wrote to `drop_rate`
/// before spawning validators (i.e., the rate for view 1). The scheduler uses
/// it to seed `active`, avoiding a redundant first-iteration write.
///
/// Clock-source note: the reporter's monitor reports the most recent
/// **finalized** view (see `consensus/src/simplex/mocks/reporter.rs::handle`).
/// When `monitor` fires with view `k`, the protocol has just finalized `k` and
/// the validators have already moved on to view `k + 1`. To realize the intent
/// "fault view v while consensus is executing view v" the lookup uses
/// `executing_view = finalized_view + 1`. The initial pre-recv lookup with
/// `finalized_view = 0` therefore covers view 1.
async fn spawn_messaging_fault_scheduler<P: simplex::Simplex>(
    context: &deterministic::Context,
    reporters: &mut [ReporterEntry<P>],
    schedule: Vec<(View, u8)>,
    required_containers: u64,
    drop_rate: network::DropRateCell,
    initial_rate: u8,
) {
    if schedule.is_empty() || reporters.is_empty() {
        return;
    }
    let Some((mut finalized_view, mut view_rx)) =
        reporter_view_stream::<P>(context, reporters).await
    else {
        return;
    };
    context
        .child("messaging_fault_scheduler")
        .spawn(move |_| async move {
            let mut active: u8 = initial_rate;
            loop {
                let executing_view = finalized_view.saturating_add(1);
                let target: u8 = schedule
                    .iter()
                    .find_map(|(view, rate)| (*view == View::new(executing_view)).then_some(*rate))
                    .unwrap_or(0);
                if target != active {
                    *drop_rate.lock() = target;
                    active = target;
                }
                if executing_view > required_containers {
                    break;
                }
                let Some(next) = view_rx.recv().await else {
                    break;
                };
                finalized_view = finalized_view.max(next);
            }
        });
}

pub(crate) fn network_faults(
    strategy: StrategyChoice,
    required_containers: u64,
    rng: &mut impl rand::Rng,
) -> Vec<(View, SetPartition)> {
    match strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => SmallScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .network_faults(required_containers, rng),
        StrategyChoice::AnyScope => AnyScope.network_faults(required_containers, rng),
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => FutureScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .network_faults(required_containers, rng),
    }
}

fn messaging_faults(
    strategy: StrategyChoice,
    required_containers: u64,
    rng: &mut impl rand::Rng,
) -> Vec<(View, u8)> {
    match strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => SmallScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .messaging_faults(required_containers, rng),
        StrategyChoice::AnyScope => AnyScope.messaging_faults(required_containers, rng),
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => FutureScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .messaging_faults(required_containers, rng),
    }
}

fn run<P: simplex::Simplex>(mut input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        if matches!(input.partition, Partition::Adaptive(_)) {
            input.partition = Partition::Adaptive(network_faults(
                input.strategy,
                input.required_containers,
                &mut context,
            ));
        }

        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;
        let initial_partition = initial_network_partition(&input.partition);
        if initial_partition.is_some() {
            apply_partition(
                &oracle,
                &participants,
                initial_partition.as_ref(),
                &default_link(),
            )
            .await;
        }

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();
        let config = input.configuration;

        // Spawn Byzantine nodes (Disrupters only)
        for i in 0..config.faults as usize {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            spawn_disrupter::<P>(ctx, schemes[i].clone(), &input, channels);
        }

        // Spawn honest validators
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let reporter = spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator.clone(),
                P::Elector::default(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                input.forwarding,
                pending,
                recovered,
                resolver,
                input.certify,
            );
            reporters.push((validator, reporter));
        }

        spawn_network_fault_scheduler::<P>(
            &context,
            &oracle,
            &participants,
            &mut reporters,
            input.partition.clone(),
            input.required_containers,
            initial_partition,
        )
        .await;

        if input.partition.is_connected() && config.is_valid() {
            let mut finalizers = Vec::new();
            for (validator, reporter) in reporters.iter_mut() {
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(
                    context
                        .child("finalizer")
                        .with_attribute("public_key", validator)
                        .spawn(move |_| async move {
                            while latest.get() < required_containers {
                                latest = monitor.recv().await.expect("event missing");
                            }
                        }),
                );
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        if config.is_valid() {
            let reporter_only: Vec<_> = reporters.iter().map(|(_, r)| r.clone()).collect();
            invariants::check_vote_invariants(config.faults as usize, &reporter_only);
            let states = invariants::extract(reporter_only, config.n as usize);
            invariants::check::<P>(config.n, states);
        }
    });
}

fn run_with_faulty_messaging<P: simplex::Simplex>(mut input: FuzzInput) {
    // FaultyMessaging is a transport-layer fault axis; topology is always fully
    // connected. Network-layer fault axes (`Static` / `Adaptive` partitions,
    // degraded link) are explicitly disabled here so the only adversarial
    // delivery effects come from the per-view messaging schedule below.
    input.partition = Partition::Connected;
    input.configuration = N4F1C3;
    input.degraded_network = false;

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        // Populate the messaging-fault schedule from the chosen strategy
        // using the deterministic FuzzRng (mirrors `Adaptive` partition path).
        input.messaging_faults =
            messaging_faults(input.strategy, input.required_containers, &mut context);

        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();
        let config = input.configuration;

        // Per-view drop-rate cell shared with every router. We seed it
        // SYNCHRONOUSLY with the rate scheduled for view 1 (the initial
        // executing view) *before* any validator is spawned: validators may
        // emit view-1 traffic on their first poll, before the async
        // `messaging_fault_scheduler` task ever runs. The scheduler picks up
        // from view 2 onward and is told `initial_rate` so it doesn't issue a
        // redundant write on its first iteration.
        let drop_rate = network::drop_rate_cell();
        let initial_rate = initial_drop_rate(&input.messaging_faults);
        *drop_rate.lock() = initial_rate;
        let byzantine_router = network::Router::new(
            context.child("byzantine_router"),
            participants
                .iter()
                .take(config.faults as usize)
                .cloned()
                .collect::<Vec<_>>(),
            drop_rate.clone(),
        );

        // Spawn Byzantine nodes (Disrupters only)
        for i in 0..config.faults as usize {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            spawn_disrupter::<P>(ctx, schemes[i].clone(), &input, channels);
        }

        // Spawn honest validators
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let reporter = spawn_honest_validator_in_faulty_messaging::<P>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator.clone(),
                byzantine_router.clone(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                input.forwarding,
                channels,
                input.certify,
            );
            reporters.push((validator, reporter));
        }

        // Spawn a per-view messaging-fault scheduler that updates the shared
        // drop-rate cell as the reference reporter advances.
        spawn_messaging_fault_scheduler::<P>(
            &context,
            &mut reporters,
            input.messaging_faults.clone(),
            input.required_containers,
            drop_rate.clone(),
            initial_rate,
        )
        .await;

        // Wait for finalization or timeout
        if input.partition.is_connected() && config.is_valid() {
            let mut finalizers = Vec::new();
            for (validator, reporter) in reporters.iter_mut() {
                let required_containers = input.required_containers;
                let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
                finalizers.push(
                    context
                        .child("finalizer")
                        .with_attribute("public_key", validator)
                        .spawn(move |_| async move {
                            while latest.get() < required_containers {
                                latest = monitor.recv().await.expect("event missing");
                            }
                        }),
                );
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }
        if config.is_valid() {
            let reporter_only: Vec<_> = reporters.iter().map(|(_, r)| r.clone()).collect();
            invariants::check_vote_invariants(config.faults as usize, &reporter_only);
            let states = invariants::extract(reporter_only, config.n as usize);
            invariants::check::<P>(config.n, states);
        }
    });
}

/// Role of the secondary half in a twin pair.
#[derive(Clone, Copy)]
enum TwinsRole {
    /// Secondary runs `Disrupter` over `input.strategy` (TwinsMutator mode).
    /// Liveness wait uses absolute view targets.
    Mutator,
    /// Secondary runs a full legitimate engine and contributes a reporter
    /// (TwinsCampaign mode). Liveness wait counts finalizations *after* the
    /// adversarial prefix.
    Campaign,
}

fn run_with_twins_mutator<P: simplex::Simplex>(input: FuzzInput) {
    run_twins::<P>(input, TwinsRole::Mutator);
}

fn run_with_twins_campaign<P: simplex::Simplex>(input: FuzzInput) {
    run_twins::<P>(input, TwinsRole::Campaign);
}

fn twins_resolver_view<P: simplex::Simplex>(
    message: &IoBuf,
    codec: &<<P::Scheme as Scheme>::Certificate as Read>::Cfg,
) -> Option<View> {
    let msg = ResolverMessage::<U64>::decode(message.clone()).ok()?;
    match msg.payload {
        ResolverPayload::Request(key) => Some(View::new(u64::from(key))),
        ResolverPayload::Response(bytes) => {
            let cert =
                Certificate::<P::Scheme, Sha256Digest>::decode_cfg(&mut bytes.as_ref(), codec)
                    .ok()?;
            Some(cert.view())
        }
        ResolverPayload::Error => None,
    }
}

/// Unified twins driver. The two existing modes (TwinsMutator / TwinsCampaign)
/// share scenario sampling, forwarders/routers, twin-half splitting, the
/// primary engine, the honest validators, and the byzantine-aware invariants.
/// Only the secondary half (Disrupter vs full engine) and the liveness wait
/// shape (absolute view vs prefix-trailing count) differ; both are keyed on
/// `role`. Invariants and liveness always run over honest reporters only.
fn run_twins<P: simplex::Simplex>(mut input: FuzzInput, role: TwinsRole) {
    input.partition = Partition::Connected;
    input.configuration = N4F1C3;

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let (mut oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &input).await;
        let participants: Arc<[_]> = participants.into();
        let n = input.configuration.n as usize;
        let faults = input.configuration.faults as usize;

        link_peers(
            &mut oracle,
            participants.as_ref(),
            Action::Update(Link {
                latency: Duration::from_millis(500),
                jitter: Duration::from_millis(500),
                success_rate: 1.0,
            }),
            input.partition.set_partition(),
        )
        .await;

        let relay = Arc::new(relay::Relay::new());
        let mut reporters = Vec::new();
        let config = input.configuration;

        // Sample a multi-round twins scenario from the deterministic FuzzRng. Both
        // the scenario (per-round partitions and scripted leaders) and the
        // compromised-assignment from the case are consumed: twin indices come from
        // `case.compromised` and the byzantine set is forwarded to
        // `check_vote_invariants_with_byzantine`.
        let mode = if rand::Rng::gen_bool(&mut context, 0.5) {
            twins::Mode::Sampled
        } else {
            twins::Mode::Sustained
        };
        let rounds = (input.required_containers as usize).clamp(1, 8);
        let cases = twins::cases(
            &mut context,
            twins::Framework {
                participants: n,
                faults,
                rounds,
                mode,
                max_cases: 16,
            },
        );
        if cases.is_empty() {
            return;
        }
        let case_idx = rand::Rng::gen_range(&mut context, 0..cases.len());
        let case = cases.into_iter().nth(case_idx).unwrap();
        let scenario = case.scenario.clone();
        let compromised: std::collections::HashSet<usize> =
            case.compromised.iter().copied().collect();

        // Twins-aware elector with scripted leaders for the first `rounds` views.
        let twin_elector = twins::Elector::new(P::Elector::default(), &scenario, n);

        // Spawn Byzantine twins (indices from `case.compromised`):
        // primary (legitimate engine) + secondary (Disrupter).
        for idx in case.compromised.iter().copied() {
            let validator = participants[idx].clone();
            let context = context.child("twin").with_attribute("index", idx);
            let scheme = schemes[idx].clone();
            let (vote_network, certificate_network, resolver_network) = registrations
                .remove(&validator)
                .expect("validator should be registered");

            let make_vote_forwarder = || {
                let participants = participants.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, _recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                        return None;
                    };
                    let (primary, secondary) =
                        scenario.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_certificate_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, _recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                        &mut message.as_ref(),
                        &codec,
                    ) else {
                        return None;
                    };
                    let (primary, secondary) =
                        scenario.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_vote_router = || {
                let participants = participants.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
                        return SplitTarget::None;
                    };
                    scenario.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Certificate::<P::Scheme, Sha256Digest>::decode_cfg(
                        &mut message.as_ref(),
                        &codec,
                    ) else {
                        return SplitTarget::None;
                    };
                    scenario.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_resolver_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, _recipients: &Recipients<_>, message: &IoBuf| {
                    let Some(view) = twins_resolver_view::<P>(message, &codec) else {
                        return None;
                    };
                    let (primary, secondary) = scenario.partitions(view, participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_resolver_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Some(view) = twins_resolver_view::<P>(message, &codec) else {
                        return SplitTarget::None;
                    };
                    scenario.route(view, sender, participants.as_ref())
                }
            };
            let (vote_sender, vote_receiver) = vote_network;
            let (certificate_sender, certificate_receiver) = certificate_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let (vote_sender_primary, vote_sender_secondary) =
                vote_sender.split_with(make_vote_forwarder());
            let (vote_receiver_primary, vote_receiver_secondary) =
                vote_receiver.split_with(context.child("pending_split"), make_vote_router());
            let (certificate_sender_primary, certificate_sender_secondary) =
                certificate_sender.split_with(make_certificate_forwarder());
            let (certificate_receiver_primary, certificate_receiver_secondary) =
                certificate_receiver
                    .split_with(context.child("recovered_split"), make_certificate_router());
            let (resolver_sender_primary, resolver_sender_secondary) =
                resolver_sender.split_with(make_resolver_forwarder());
            let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                .split_with(context.child("resolver_split"), make_resolver_router());

            // Primary: legitimate engine driven by the twins-aware elector.
            let primary_context = context.child("primary");
            let primary_elector = twin_elector.clone();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_ref()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: primary_elector.clone(),
            };
            let reporter = reporter::Reporter::new(primary_context.child("reporter"), reporter_cfg);

            let app_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Always,
            };
            let (actor, application) =
                application::Application::new(primary_context.child("application"), app_cfg);
            actor.start();

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: scheme.clone(),
                elector: primary_elector,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("twin_{idx}_primary"),
                mailbox_size: NZUsize!(1024),
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_millis(1_500),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: NZUsize!(1),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&primary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: input.forwarding,
            };
            let engine = Engine::new(primary_context.child("engine"), engine_cfg);
            engine.start(
                (vote_sender_primary, vote_receiver_primary),
                (certificate_sender_primary, certificate_receiver_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );
            // Push the primary reporter only in `Campaign`; `Mutator` keeps
            // its existing semantics where invariants run only on honest
            // reporters and twin primary is excluded by construction.
            if matches!(role, TwinsRole::Campaign) {
                reporters.push(reporter.clone());
            }

            // Secondary: depends on role.
            match role {
                TwinsRole::Mutator => {
                    start_disrupter::<P>(
                        context.child("secondary"),
                        scheme.clone(),
                        &input.strategy,
                        input.required_containers,
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    );
                }
                TwinsRole::Campaign => {
                    let secondary_label = format!("twin_{idx}_secondary");
                    let secondary_context = context.child("secondary");
                    let secondary_elector = twin_elector.clone();
                    let secondary_reporter_cfg = reporter::Config {
                        participants: participants
                            .as_ref()
                            .try_into()
                            .expect("public keys are unique"),
                        scheme: scheme.clone(),
                        elector: secondary_elector.clone(),
                    };
                    let secondary_reporter = reporter::Reporter::new(
                        secondary_context.child("reporter"),
                        secondary_reporter_cfg,
                    );
                    reporters.push(secondary_reporter.clone());

                    let secondary_app_cfg = application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: application::Certifier::Always,
                    };
                    let (secondary_actor, secondary_application) = application::Application::new(
                        secondary_context.child("application"),
                        secondary_app_cfg,
                    );
                    secondary_actor.start();

                    let secondary_blocker = oracle.control(validator.clone());
                    let secondary_engine_cfg = config::Config {
                        blocker: secondary_blocker,
                        scheme: scheme.clone(),
                        elector: secondary_elector,
                        automaton: secondary_application.clone(),
                        relay: secondary_application.clone(),
                        reporter: secondary_reporter,
                        partition: secondary_label,
                        mailbox_size: NZUsize!(1024),
                        epoch: Epoch::new(EPOCH),
                        leader_timeout: Duration::from_secs(1),
                        certification_timeout: Duration::from_millis(1_500),
                        timeout_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout: Delta::new(10),
                        skip_timeout: Delta::new(5),
                        fetch_concurrent: NZUsize!(1),
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::from_pooler(
                            &secondary_context,
                            PAGE_SIZE,
                            PAGE_CACHE_SIZE,
                        ),
                        strategy: Sequential,
                        forwarding: input.forwarding,
                    };
                    let secondary_engine =
                        Engine::new(secondary_context.child("engine"), secondary_engine_cfg);
                    secondary_engine.start(
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    );
                }
            }
        }

        // Boundary in `reporters`. For `Mutator` no twin reporters were pushed,
        // so `honest_start = 0`; for `Campaign` it's `2 * compromised.len()`.
        let honest_start = reporters.len();

        // Spawn honest validators (every index NOT in `case.compromised`).
        // They share the twins-aware elector so leaders agree across twin and
        // honest engines for the scripted prefix.
        for (idx, validator) in participants.iter().enumerate() {
            if compromised.contains(&idx) {
                continue;
            }
            let ctx = context.child("honest").with_attribute("index", idx);
            let (pending, recovered, resolver) = registrations
                .remove(validator)
                .expect("validator should be registered");
            let reporter = spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                ctx,
                &oracle,
                participants.as_ref(),
                schemes[idx].clone(),
                validator.clone(),
                twin_elector.clone(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_millis(1_500),
                input.forwarding,
                pending,
                recovered,
                resolver,
                input.certify,
            );
            reporters.push(reporter);
        }

        // Wait for liveness on honest reporters only. The wait shape depends on
        // role: `Mutator` uses absolute view targets, `Campaign` counts
        // finalizations after the adversarial prefix.
        if config.is_valid() {
            let prefix_end = View::new(scenario.rounds().len() as u64);
            let mut finalizers = Vec::new();
            for (i, reporter) in reporters.iter_mut().skip(honest_start).enumerate() {
                let required = input.required_containers;
                match role {
                    TwinsRole::Mutator => {
                        let (mut latest, mut monitor): (View, Receiver<View>) =
                            reporter.subscribe().await;
                        finalizers.push(
                            context.child("finalizer").with_attribute("index", i).spawn(
                                move |_| async move {
                                    while latest.get() < required {
                                        latest = monitor.recv().await.expect("event missing");
                                    }
                                },
                            ),
                        );
                    }
                    TwinsRole::Campaign => {
                        let (_latest, mut monitor) = reporter.subscribe().await;
                        finalizers.push(
                            context.child("finalizer").with_attribute("index", i).spawn(
                                move |_| async move {
                                    let mut count = 0u64;
                                    while count < required {
                                        let view = monitor.recv().await.expect("event missing");
                                        if view > prefix_end {
                                            count += 1;
                                        }
                                    }
                                },
                            ),
                        );
                    }
                }
            }
            join_all(finalizers).await;
        } else {
            context.sleep(MAX_SLEEP_DURATION).await;
        }

        // Invariants on honest reporters only. Twin halves (when present) are
        // expected to disagree internally per the scenario; checking them in
        // global-agreement / equivocation invariants would reject valid Twins
        // configurations.
        if config.is_valid() {
            let honest_reporters = &reporters[honest_start..];
            invariants::check_vote_invariants_with_byzantine(&compromised, honest_reporters);
            let states = invariants::extract(
                reporters.into_iter().skip(honest_start).collect(),
                config.n as usize,
            );
            invariants::check::<P>(config.n, states);
        }
    });
}

fn run_fuzz_node<P: simplex::Simplex, M: simplex_node::NodeFuzzMode>(input: NodeFuzzInput)
where
    PublicKeyOf<P>: Send,
{
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let forwarding = input.forwarding;
    let certify = input.certify;

    match M::MODE {
        simplex_node::NodeMode::WithoutRecovery => {
            executor.start(|mut context| async move {
                let _ = simplex_node::run::<P>(&mut context, &input).await;
            });
        }
        simplex_node::NodeMode::WithRecovery => {
            let ((participants, schemes), checkpoint) =
                executor.start_and_recover(|mut context| async move {
                    simplex_node::run::<P>(&mut context, &input).await
                });
            simplex_node::run_recovery::<P>(checkpoint, participants, schemes, forwarding, certify);
        }
    }
}

/// Selector for which a fuzz harness will dispatch to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Standard,
    TwinsMutator,
    TwinsCampaign,
    FaultyMessaging,
    FaultyNet,
    Byzzfuzz,
}

pub trait FuzzMode {
    const MODE: Mode;
}

/// **Standard mode** - the baseline harness.
///
/// Configured byzantine validators run as `Disrupter` (mutating outgoing messages
/// per `input.strategy`); the remaining validators run honestly. Network
/// topology follows `input.partition` (`Connected`, a `Static` set partition,
/// or an `Adaptive` round-indexed schedule).
///
/// Use this for general protocol-level fuzzing of consensus under byzantine
/// message mutations and optional partition faults.
pub struct Standard;
impl FuzzMode for Standard {
    const MODE: Mode = Mode::Standard;
}

/// **TwinsMutator mode** - twin pairs with a `Disrupter` on the secondary half.
///
/// Each compromised participant (from a sampled `twins::cases` scenario) runs
/// two halves: a legitimate primary engine and a secondary `Disrupter` that
/// equivocates per `input.strategy`. The two halves see different network
/// views per the scenario's per-round partitions, and all engines use the
/// twins-aware elector for scripted leaders.
///
/// Use this to fuzz byzantine *content* mutations layered on top of twins-style
/// network splits.
pub struct TwinsMutator;
impl FuzzMode for TwinsMutator {
    const MODE: Mode = Mode::TwinsMutator;
}

/// **TwinsCampaign mode** - twin pairs where both halves are full engines.
///
/// Mirrors `consensus/src/simplex/mod.rs::twins_campaign`: no `Disrupter`,
/// both halves run as legitimate engines under the twins-aware elector and
/// see different network partitions per round. Liveness counts finalizations
/// only past the adversarial prefix; safety invariants run only over honest
/// reporters.
pub struct TwinsCampaign;
impl FuzzMode for TwinsCampaign {
    const MODE: Mode = Mode::TwinsCampaign;
}

/// **FaultyMessaging mode** - message-delivery faults at the transport layer.
///
/// Topology is fully connected (`Partition::Connected` is enforced).
///
/// Two transport-layer effects are layered on top of the full mesh:
/// - **Byzantine-first ordering** (uniform, always-on): `ByzantineFirstReceiver`
///   reorders the receive queue so byzantine-origin messages are processed
///   before honest ones whenever both are available. This effect does not
///   vary per view.
/// - **Honest-message drop rate** (round-indexed): a per-view schedule
///   generated by `Strategy::messaging_faults` from the deterministic
///   FuzzRng drives the shared [`network::DropRateCell`] consulted on every
///   routing decision. Outside scheduled views the rate is 0. The view-1
///   rate is written synchronously before validators are spawned so the
///   scheduled rate takes effect from the protocol's first message; the
///   async scheduler task picks up from view 2 onward.
pub struct FaultyMessaging;
impl FuzzMode for FaultyMessaging {
    const MODE: Mode = Mode::FaultyMessaging;
}

/// **FaultyNet mode** - round-indexed set-partition faults at the network layer.
///
/// Coerces `input.partition` to `Adaptive(_)` so the per-view fault scheduler
/// activates a sampled `SetPartition` for each scheduled view, reverting to
/// fully connected outside scheduled views. Each strategy guarantees at least
/// one entry, so every run exercises an actual partition window.
pub struct FaultyNet;
impl FuzzMode for FaultyNet {
    const MODE: Mode = Mode::FaultyNet;
}

/// **Byzzfuzz mode** - sampled network and process faults checked against
/// safety *and* liveness on every run.
///
/// Runs four honest engines plus a per-message intercept layer. Faults are
/// sampled per iteration:
/// - **Network faults**: a schedule of `(view, partition)` entries. At a
///   scheduled view, traffic across partition blocks is dropped on every
///   channel (vote, certificate, resolver, even undecodable bytes); outside
///   scheduled views the topology is fully connected.
/// - **Process faults**: a fixed byzantine identity (always at index 0),
///   whose outgoing protocol messages are intercepted per a schedule of
///   `(view, receivers, action, message_scope)` entries. `message_scope`
///   optionally narrows a fault to a specific channel + message kind (e.g.
///   only Notarize votes); `Any` does not narrow the channel/kind. `action`
///   either omits targeted delivery or semantically mutates a vote and
///   re-signs it under the byzantine identity. Certificate and resolver
///   process faults are omit-only.
///
/// Round attribution uses each message sender's current protocol round
/// (the maximum view that sender has sent or received) for network faults.
/// Process faults use the decoded view carried by the byzantine message
/// itself. Retransmissions of an old view at a later sender round can be
/// filtered by that later round's network partition, but they do not inherit
/// process faults scheduled for the later round.
///
/// Network faults apply during a bounded fault phase. If all non-byzantine
/// reporters reach `required_containers` during that phase, the run skips GST
/// and proceeds to safety checks. Otherwise, the shared fault gate reaches GST:
/// partitions pass through, but the byzantine sender keeps mutating/omitting
/// its own messages under the same `(view, receivers, action, scope)` schedule
/// extended with a fresh post-GST view budget. Each non-byzantine reporter
/// below `required_containers` at GST must reach `required_containers`; each
/// reporter already at or above it must finalize above its baseline. Failure to
/// reach the post-GST target panics with a liveness violation. See
/// [`byzzfuzz::run`].
pub struct Byzzfuzz;
impl FuzzMode for Byzzfuzz {
    const MODE: Mode = Mode::Byzzfuzz;
}

/// Install (once per process) a panic-hook chain that drains and prints the
/// ByzzFuzz decision log when the `CONSENSUS_FUZZ_LOG` environment variable is
/// set (any value). Off by default to keep the libfuzzer crash output
/// terse. The log is dumped *before* the previous hook runs: libfuzzer-sys
/// installs a panic hook that prints + `abort()`s the process, so anything
/// queued after it would never reach the terminal. With this ordering the
/// output reads: log -> default panic message -> libfuzzer stack trace /
/// `Failing input` / `Debug`.
fn install_byzzfuzz_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        // Sample the env var once at install time -- the hook itself runs
        // in panic context and shouldn't touch global env state.
        let dump = std::env::var_os(FUZZ_LOG_ENV).is_some();
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if dump {
                let log = byzzfuzz::log::take();
                if !log.is_empty() {
                    eprintln!("---- ByzzFuzz decision log ({} entries) ----", log.len());
                    for line in &log {
                        eprintln!("{line}");
                    }
                    eprintln!("---- end of ByzzFuzz decision log ----");
                }
            }
            prev(info);
        }));
    });
}

pub fn fuzz<P: simplex::Simplex, M: FuzzMode>(mut input: FuzzInput) {
    // TODO: enabled it again after the application mock support forwarding policies
    // or remove this mode entirely from fuzzing
    input.forwarding = ForwardingPolicy::Disabled;

    if matches!(M::MODE, Mode::Byzzfuzz) {
        install_byzzfuzz_panic_hook();
    } else {
        if matches!(M::MODE, Mode::FaultyNet) {
            // We run only fuzzing with network faults, populated later by the
            // chosen strategy.
            input.partition = Partition::Adaptive(Vec::new());
        }
        print_fuzz_input(M::MODE, &input);
    }

    let raw_bytes = input.raw_bytes.clone();
    let run_result = match M::MODE {
        Mode::Standard => panic::catch_unwind(panic::AssertUnwindSafe(|| run::<P>(input))),
        Mode::FaultyMessaging => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_faulty_messaging::<P>(input)
        })),
        Mode::FaultyNet => panic::catch_unwind(panic::AssertUnwindSafe(|| run::<P>(input))),
        Mode::TwinsMutator => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twins_mutator::<P>(input)
        })),
        Mode::TwinsCampaign => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twins_campaign::<P>(input)
        })),
        Mode::Byzzfuzz => {
            panic::catch_unwind(panic::AssertUnwindSafe(|| byzzfuzz::run::<P>(input)))
        }
    };
    match run_result {
        Ok(()) => {
            // Drain the byzzfuzz log on success too so a *next* run (Byzzfuzz
            // or otherwise) starts clean. This is cheap when the log is empty.
            if matches!(M::MODE, Mode::Byzzfuzz) {
                let _ = byzzfuzz::log::take();
            }
        }
        Err(payload) => {
            println!("Panicked with raw_bytes: {:?}", raw_bytes);
            // The ByzzFuzz decision log is dumped by the panic hook
            // installed in `install_byzzfuzz_panic_hook` (fires during the
            // panic itself, before unwinding reaches here). No work needed
            // in this arm.
            panic::resume_unwind(payload);
        }
    }
}

pub fn fuzz_node<P: simplex::Simplex, M: simplex_node::NodeFuzzMode>(mut input: NodeFuzzInput) {
    // TODO: enabled it again after the application mock support forwarding policies
    // or remove this mode entirely from fuzzing
    input.forwarding = ForwardingPolicy::Disabled;

    print_node_fuzz_input(M::MODE, &input);

    let raw_bytes_for_panic = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| run_fuzz_node::<P, M>(input)));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes_for_panic);
        panic::resume_unwind(payload);
    }
}

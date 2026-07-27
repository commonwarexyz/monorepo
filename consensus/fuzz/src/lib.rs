#[cfg(feature = "mocks")]
pub mod aggregation;
#[cfg(feature = "mocks")]
pub mod aggregation_certificate_mock;
#[cfg(feature = "mocks")]
pub mod aggregation_decode;
pub mod bounds;
pub mod byzzfuzz;
pub mod disrupter;
pub mod happens_before;
pub mod id_mock;
pub mod invariants;
pub(crate) mod mallory;
#[cfg(feature = "mocks")]
pub mod marshal;
pub mod network;
#[cfg(feature = "mocks")]
pub mod ordered_broadcast;
#[cfg(feature = "mocks")]
pub mod ordered_broadcast_certificate_mock;
pub mod simplex;
pub(crate) mod simplex_audit;
#[cfg(feature = "mocks")]
pub mod simplex_certificate_mock;
pub mod simplex_node;
pub mod state_cov;
pub mod strategy;
mod twins_network;
pub mod types;
pub mod utils;
use crate::{
    disrupter::Disrupter,
    network::ByzantineFirstReceiver,
    simplex_audit::{RecordingAutomaton, RecordingReporter, summaries},
    simplex_node::NodeFuzzInput,
    strategy::{
        AnyScope, FutureScope, HeaderScope, SmallScope, SplitHeader, Strategy, StrategyChoice,
    },
    utils::{Action, Partition, SetPartition, apply_partition, link_peers, register},
};
use arbitrary::Arbitrary;
use commonware_actor::Feedback;
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{
    Monitor, Reporter, Reporters, Viewable,
    simplex::{
        Engine, Floor, ForwardingPolicy, config,
        elector::Config as ElectorConfig,
        mocks::{application, relay, reporter, twins},
        types::{Certificate, Vote},
    },
    types::{Delta, Epoch, TermLength, View},
};
use commonware_cryptography::{
    PublicKey as CryptoPublicKey, Sha256, certificate::Verifier, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::{
    Clock, Handle, IoBuf, Metrics, Runner, Spawner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic,
    telemetry::traces::collector::{CollectingLayer, TraceStorage},
};
use commonware_utils::{
    FuzzRng, NZU16, NZU32, NZUsize,
    channel::mpsc::{self, Receiver},
    sequence::U64,
    sync::Once,
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
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    num::{NonZeroU16, NonZeroUsize},
    panic,
    sync::Arc,
    time::Duration,
};
use tracing::{Dispatch, Level, dispatcher};
use tracing_subscriber::{Layer as _, filter::filter_fn, layer::SubscriberExt};
pub const EPOCH: u64 = 333;

const FUZZ_LOG_ENV: &str = "CONSENSUS_FUZZ_LOG";

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
/// Index of the byzantine validator in `participants`. Single source of truth
/// for the fixed byzantine identity used by the ByzzFuzz and marshal multi-node
/// models (sender selection, injector key, invariant/liveness exclusion).
pub(crate) const BYZANTINE_IDX: usize = 0;
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
pub(crate) const MAX_SLEEP_DURATION: Duration = Duration::from_secs(15);
/// Bounded pre-GST fault phase: how long network faults stay active before a
/// run that has not already finished is given a GST transition. Shared by the
/// ByzzFuzz runner and the marshal multi-node liveness runner.
pub(crate) const FAULT_PHASE: Duration = Duration::from_secs(30);
/// Bounded post-GST window: how long honest nodes have to recover once the
/// network heals (process/byzantine faults stay active). Shared by the ByzzFuzz
/// runner and the marshal multi-node liveness runner.
pub(crate) const POST_GST_WINDOW: Duration = Duration::from_secs(360);
const NAMESPACE: &[u8] = b"consensus_fuzz";
const MAX_RAW_BYTES: usize = 32_768;
const DEFAULT_MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const DEFAULT_FETCH_CONCURRENT: NonZeroUsize = NZUsize!(1);

pub(crate) fn fuzz_mailbox_size(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<NonZeroUsize> {
    Ok(match u.int_in_range(0..=99)? {
        0..=49 => DEFAULT_MAILBOX_SIZE,
        50..=74 => NZUsize!(1),
        75..=89 => NZUsize!(2),
        90..=96 => NZUsize!(4),
        _ => NZUsize!(8),
    })
}

pub(crate) fn fuzz_fetch_concurrent(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<NonZeroUsize> {
    Ok(match u.int_in_range(0..=99)? {
        0..=49 => DEFAULT_FETCH_CONCURRENT,
        50..=74 => NZUsize!(2),
        75..=89 => NZUsize!(4),
        _ => NZUsize!(8),
    })
}

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
/// `SingleCancel` and `SinglePending` apply their non-default certifier only to
/// `target_idx`. `RejectView` applies the same deterministic rejection rule to
/// every correct validator and is valid only when that view's proposer is
/// Byzantine. Dedicated audit targets enforce that precondition before using
/// it, preserving both certification consistency and the correct proposer's
/// certifiable-by-construction obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifyChoice {
    Always,
    SingleCancel { target_idx: u8 },
    SinglePending { target_idx: u8 },
    RejectView { view: View },
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
            CertifyChoice::RejectView { view } => {
                application::Certifier::Custom(Box::new(move |round, _| round.view() != view))
            }
        }
    }
}

/// Per-iteration shape of the [Reporters] combinator wrapping each honest
/// engine's reporter, driving coverage of `commonware_consensus::reporter`.
/// Compromised twin engines keep raw reporters. The real reporter is always
/// present so liveness checks keep working; the variant picks its slot and
/// what (if anything) occupies the other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReporterWiring {
    /// `(Some(real), None)`
    Solo,
    /// `(None, Some(Some(real)))`
    SecondSlot,
    /// `(Some(real), Some(None))`
    EmptySlot,
    /// `(Some(real), Some(Some(probe)))`
    ProbeSecond(Feedback),
    /// `(Some(probe), Some(Some(real)))`
    ProbeFirst(Feedback),
}

impl Arbitrary<'_> for ReporterWiring {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let feedback = |u: &mut arbitrary::Unstructured<'_>| {
            Ok(match u.int_in_range(0..=2)? {
                0 => Feedback::Ok,
                1 => Feedback::Backoff,
                _ => Feedback::Closed,
            })
        };
        Ok(match u.int_in_range(0..=4)? {
            0 => Self::Solo,
            1 => Self::SecondSlot,
            2 => Self::EmptySlot,
            3 => Self::ProbeSecond(feedback(u)?),
            _ => Self::ProbeFirst(feedback(u)?),
        })
    }
}

impl ReporterWiring {
    fn wire<R: Reporter>(self, real: R) -> WiredReporter<R> {
        let real = FuzzReporter::Real(real);
        match self {
            Self::Solo => Reporters::from((real, None::<Option<FuzzReporter<R>>>)),
            Self::SecondSlot => Reporters::from((None::<FuzzReporter<R>>, Some(real))),
            Self::EmptySlot => Reporters::from((real, None::<FuzzReporter<R>>)),
            Self::ProbeSecond(feedback) => {
                Reporters::from((real, Some(FuzzReporter::Probe(feedback))))
            }
            Self::ProbeFirst(feedback) => {
                Reporters::from((Some(FuzzReporter::Probe(feedback)), Some(real)))
            }
        }
    }
}

/// Slot occupant for [ReporterWiring]: the real reporter or a probe that
/// returns a fixed [Feedback], exercising `combine` with non-`Ok` values
/// (the engine discards reporter feedback, so any value is liveness-safe).
#[derive(Clone)]
pub(crate) enum FuzzReporter<R> {
    Real(R),
    Probe(Feedback),
}

impl<R: Reporter> Reporter for FuzzReporter<R> {
    type Activity = R::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match self {
            Self::Real(reporter) => reporter.report(activity),
            Self::Probe(feedback) => *feedback,
        }
    }
}

type WiredReporter<R> =
    Reporters<<R as Reporter>::Activity, FuzzReporter<R>, Option<FuzzReporter<R>>>;

struct FuzzInputDebug<'a>(&'a FuzzInput);

impl fmt::Debug for FuzzInputDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let input = self.0;
        f.debug_struct("FuzzInput")
            .field("raw_bytes_len", &input.raw_bytes.len())
            .field("required_containers", &input.required_containers)
            .field("term_length", &input.term_length)
            .field("degraded_network", &input.degraded_network)
            .field("configuration", &input.configuration)
            .field("partition", &input.partition)
            .field("strategy", &input.strategy)
            .field("messaging_faults", &input.messaging_faults)
            .field("mailbox_size", &input.mailbox_size)
            .field("fetch_concurrent", &input.fetch_concurrent)
            .field("forwarding", &input.forwarding)
            .field("certify", &input.certify)
            .field("reporting", &input.reporting)
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
            .field("term_length", &input.term_length)
            .field("mailbox_size", &input.mailbox_size)
            .field("fetch_concurrent", &input.fetch_concurrent)
            .field("forwarding", &input.forwarding)
            .field("certify", &input.certify)
            .field("reporting", &input.reporting)
            .finish()
    }
}

fn print_fuzz_input<P: simplex::Simplex>(mode: Mode, input: &FuzzInput) {
    if std::env::var_os(FUZZ_LOG_ENV).is_some() {
        eprintln!(
            "consensus fuzz configuration: mode={mode:?} effective_term_length={:?} input={:?}",
            P::effective_term_length(input.term_length),
            FuzzInputDebug(input)
        );
    }
}

fn print_node_fuzz_input<P: simplex::Simplex>(mode: simplex_node::NodeMode, input: &NodeFuzzInput) {
    if std::env::var_os(FUZZ_LOG_ENV).is_some() {
        eprintln!(
            "consensus node fuzz configuration: mode={mode:?} effective_term_length={:?} input={:?}",
            P::effective_term_length(input.term_length),
            NodeFuzzInputDebug(input)
        );
    }
}

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub term_length: TermLength,
    pub degraded_network: bool,
    pub configuration: Configuration,
    pub partition: Partition,
    pub strategy: StrategyChoice,
    /// Round-indexed schedule of honest-message drop rates, used only by
    /// `Mode::FaultyMessaging`. Each entry `(view, rate)` activates an
    /// `rate%` honest-message drop while the reference reporter is in `view`;
    /// the rate reverts to 0 outside scheduled views.
    pub messaging_faults: Vec<(View, u8)>,
    /// Per-iteration mailbox capacity threaded into every honest engine.
    pub mailbox_size: NonZeroUsize,
    /// Per-iteration resolver fetch concurrency threaded into every honest engine.
    pub fetch_concurrent: NonZeroUsize,
    /// Per-iteration forwarding policy threaded into every engine the harness
    /// spawns. Sampling lets the fuzzer drive coverage of all three arms of
    /// `batcher::forward_targets` instead of pinning to `Disabled`.
    pub forwarding: ForwardingPolicy,
    /// Per-iteration certify policy threaded into every honest validator
    /// the harness spawns.
    pub certify: CertifyChoice,
    /// Per-iteration reporter wiring threaded into every honest engine
    /// the harness spawns.
    pub reporting: ReporterWiring,
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
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=5)?));

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

        // Single-target cancel/pending variants require N4F0C4, where disabling
        // one certifier still leaves a finalize quorum. Rejected certification
        // is enabled separately by dedicated audit targets only when their
        // statically known leader schedule selects the Byzantine participant.
        let certify = if configuration == N4F0C4 {
            let target_idx = u.int_in_range(0..=configuration.n as u8 - 1)?;
            match u.int_in_range(0..=4)? {
                0 => CertifyChoice::SingleCancel { target_idx },
                1 => CertifyChoice::SinglePending { target_idx },
                _ => CertifyChoice::Always,
            }
        } else {
            CertifyChoice::Always
        };

        let reporting = ReporterWiring::arbitrary(u)?;

        let mailbox_size = fuzz_mailbox_size(u)?;
        let fetch_concurrent = fuzz_fetch_concurrent(u)?;

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
            term_length,
            strategy,
            messaging_faults: Vec::new(),
            mailbox_size,
            fetch_concurrent,
            forwarding,
            certify,
            reporting,
        })
    }
}

pub(crate) type PublicKeyOf<P> = <<P as simplex::Simplex>::Scheme as Verifier>::PublicKey;
pub(crate) type CertCfgOf<P> =
    <<<P as simplex::Simplex>::Scheme as Verifier>::Certificate as commonware_codec::Read>::Cfg;
/// Happens-before sink for a [`SniffingReceiver`].
pub(crate) struct Sniff<P: simplex::Simplex> {
    /// Receiving node id events are attributed to.
    node: u32,
    /// Shared event log.
    log: happens_before::capture::EventLog,
    /// Participant set used to resolve wire senders to node ids.
    peers: Arc<[PublicKeyOf<P>]>,
    /// Participant indices whose identity is ambiguous (a twin pair runs two
    /// engines under one key): a receive from them resolves to no sender, so
    /// neither half's history can be merged.
    ambiguous: Arc<[u32]>,
}

pub(crate) type SniffSink<P> = Option<Sniff<P>>;

pub(crate) fn sniff_sink<P: simplex::Simplex>(
    hb_log: &Option<happens_before::capture::EventLog>,
    node: u32,
    peers: &Arc<[PublicKeyOf<P>]>,
    ambiguous: &Arc<[u32]>,
) -> SniffSink<P> {
    hb_log.as_ref().map(|log| Sniff {
        node,
        log: log.clone(),
        peers: peers.clone(),
        ambiguous: ambiguous.clone(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunAudit {
    auditor_state: String,
    reporter_states: BTreeMap<String, types::ReporterReplicaStateData>,
    happens_before: Option<happens_before::Summary>,
}

pub(crate) type NetworkChannels<P> = (
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

/// Start a Disrupter with the given strategy and network channels, using the
/// harness-wide [`EPOCH`] for emitted messages.
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
    start_disrupter_with_epoch::<P>(
        context,
        scheme,
        strategy,
        required_containers,
        Epoch::new(EPOCH),
        vote_network,
        certificate_network,
        resolver_network,
    );
}

/// Like [`start_disrupter`] but stamps emitted byzantine messages with `epoch`.
/// The marshal liveness target passes `Epoch::zero()` so the disrupter shares
/// the epoch its honest engines run in (making it an in-epoch adversary rather
/// than wrong-epoch noise).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_disrupter_with_epoch<P: simplex::Simplex>(
    context: deterministic::Context,
    scheme: P::Scheme,
    strategy: &StrategyChoice,
    required_containers: u64,
    epoch: Epoch,
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
            let disrupter = Disrupter::new_with_epoch(
                context,
                scheme,
                SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
                epoch,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::AnyScope => {
            let disrupter =
                Disrupter::new_with_epoch(context, scheme, AnyScope, required_containers, epoch);
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new_with_epoch(
                context,
                scheme,
                FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
                epoch,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::HeaderScope {
            fault_rounds,
            fault_rounds_bound,
            mutation,
        } => {
            let disrupter = Disrupter::new_with_epoch(
                context,
                scheme,
                HeaderScope {
                    fault_rounds,
                    fault_rounds_bound,
                    mutation,
                },
                required_containers,
                epoch,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::SplitHeader {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new_with_epoch(
                context,
                scheme,
                SplitHeader {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
                epoch,
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

/// Whether a [`ManagedValidator`]'s engine is running, has been crash-stopped, or
/// was restarted with empty storage.
/// A crash-stop is permanent for the crashed INCARNATION but not terminal for the
/// run: after [`Running`](Self::Running) transitions to [`Crashed`](Self::Crashed)
/// the old engine/application tasks are aborted and never resurrected, yet the
/// episode continues over the surviving quorum (the crashed node is dropped from the
/// liveness watch; its retained reporter stays in the safety set). A durable restart
/// is a separate fault that rebuilds fresh tasks and returns to `Running` in one
/// step, so it never leaves the node in `Crashed` (see `crate::mallory::lifecycle`).
/// An [`Amnesiac`](Self::Amnesiac) node has a LIVE engine but was rebuilt on a fresh
/// (empty) storage partition, so it has forgotten its durable state (including signed
/// votes) and may equivocate: it is treated as Byzantine for the rest of the episode
/// (excluded from the honest safety and liveness sets), not terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ValidatorLifecycle {
    /// The engine and application tasks are live.
    Running,
    /// The engine and application tasks were aborted and awaited to termination.
    Crashed,
    /// The engine was rebuilt on a fresh (empty) storage partition: it has forgotten
    /// its durable state and is treated as Byzantine for the rest of the episode.
    Amnesiac,
}

/// An honest validator whose engine/application task handles are RETAINED (not
/// dropped) so its lifecycle can be managed at runtime: crash-stopped or durably
/// restarted (Mallory mode, PR5+). The reporter is Arc-backed, so its safety
/// history survives a crash and a clone reflects the live engine's state.
///
/// `EC` defaults to the backend's own elector so most callers write
/// `ManagedValidator<P>`; the generic form exists only so the general
/// [`build_validator`] can carry whatever elector its caller passed.
pub(crate) struct ManagedValidator<P, EC = <P as simplex::Simplex>::Elector>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    /// Index of this validator in the participant set (its faultable identity).
    idx: usize,
    /// This validator's public key; re-registration and rebuild target it.
    validator: PublicKeyOf<P>,
    /// This validator's signing scheme, retained so a rebuild reuses it.
    scheme: P::Scheme,
    /// Durable storage partition; a durable restart replays it, so it is kept
    /// stable across incarnations.
    partition: String,
    /// Incarnation counter (0 at first build), bumped on each restart. The seam a
    /// later amnesia restart uses to derive a fresh partition.
    generation: u32,
    /// Arc-backed reporter; a restart reuses this instance to retain pre-crash
    /// safety history.
    reporter: reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>,
    /// Application actor handle, retained so a crash can abort it. `None` once
    /// taken by a crash/restart.
    app_handle: Option<Handle<()>>,
    /// Engine handle, retained so a crash can abort it (aborting cascades to every
    /// engine sub-task). `None` once taken by a crash/restart.
    engine_handle: Option<Handle<()>>,
    /// Whether the engine is currently running or has been crash-stopped.
    lifecycle: ValidatorLifecycle,
}

impl<P, EC> ManagedValidator<P, EC>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    /// A clone of the Arc-backed reporter (shares live state with this validator).
    pub(crate) fn reporter(
        &self,
    ) -> reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest> {
        self.reporter.clone()
    }

    /// This validator's index in the participant set.
    pub(crate) fn idx(&self) -> usize {
        self.idx
    }

    /// This validator's public key.
    pub(crate) fn validator(&self) -> &PublicKeyOf<P> {
        &self.validator
    }

    /// This validator's signing scheme.
    pub(crate) fn scheme(&self) -> &P::Scheme {
        &self.scheme
    }

    /// The durable storage partition (stable across incarnations).
    pub(crate) fn partition(&self) -> &str {
        &self.partition
    }

    /// The current lifecycle state.
    pub(crate) fn lifecycle(&self) -> ValidatorLifecycle {
        self.lifecycle
    }

    /// Take the engine handle for a crash/restart abort, leaving `None`.
    pub(crate) fn take_engine_handle(&mut self) -> Option<Handle<()>> {
        self.engine_handle.take()
    }

    /// Take the application handle for a crash/restart abort, leaving `None`.
    pub(crate) fn take_app_handle(&mut self) -> Option<Handle<()>> {
        self.app_handle.take()
    }

    /// Mark the engine crash-stopped after both handles were aborted and awaited.
    pub(crate) fn mark_crashed(&mut self) {
        self.lifecycle = ValidatorLifecycle::Crashed;
    }

    /// Adopt a freshly rebuilt incarnation: take over its engine/application
    /// handles, bump the generation, and return to `Running`. The reporter is
    /// unchanged (a durable restart reuses the same instance).
    pub(crate) fn adopt(&mut self, rebuilt: ManagedValidator<P, EC>) {
        self.app_handle = rebuilt.app_handle;
        self.engine_handle = rebuilt.engine_handle;
        self.generation = self.generation.wrapping_add(1);
        self.lifecycle = ValidatorLifecycle::Running;
    }

    /// Adopt an amnesia-restarted incarnation: take over its engine/application
    /// handles and its FRESH storage partition and reporter (the rebuild used an
    /// empty partition and a clean-slate reporter), bump the generation, and mark
    /// the node [`Amnesiac`](ValidatorLifecycle::Amnesiac). Unlike [`adopt`](Self::adopt)
    /// this replaces the partition and reporter, because the node forgot its durable
    /// state and its new incarnation owns a distinct storage and history.
    pub(crate) fn adopt_amnesiac(&mut self, rebuilt: ManagedValidator<P, EC>) {
        self.app_handle = rebuilt.app_handle;
        self.engine_handle = rebuilt.engine_handle;
        self.partition = rebuilt.partition;
        self.reporter = rebuilt.reporter;
        self.generation = self.generation.wrapping_add(1);
        self.lifecycle = ValidatorLifecycle::Amnesiac;
    }

    /// This validator's current incarnation counter.
    pub(crate) fn generation(&self) -> u32 {
        self.generation
    }
}

/// Spawn an honest validator with application, reporter, and engine, returning
/// only its reporter. A thin wrapper over [`build_validator`] preserved so its
/// many existing callers compile unchanged.
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
    mailbox_size: NonZeroUsize,
    fetch_concurrent: NonZeroUsize,
    forwarding: ForwardingPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
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
    build_validator::<P, EC, _, _, _, _, _, _>(
        context,
        oracle,
        participants,
        scheme,
        validator,
        elector,
        relay,
        leader_timeout,
        certification_timeout,
        mailbox_size,
        fetch_concurrent,
        forwarding,
        pending,
        recovered,
        resolver,
        certify,
        wiring,
    )
    .reporter
}

/// Spawn an honest validator instrumented with the fuzz-only append-only
/// reporter and automaton history.
///
/// This is intentionally separate from [`spawn_honest_validator`]. Non-audit
/// fuzz targets continue to instantiate the consensus mock reporter and mock
/// application automaton directly; only dedicated audit targets call this
/// constructor.
#[allow(clippy::too_many_arguments)]
fn spawn_audited_validator<
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
    mailbox_size: NonZeroUsize,
    fetch_concurrent: NonZeroUsize,
    forwarding: ForwardingPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> RecordingReporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
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
    let reporter = RecordingReporter::new(
        context.child("reporter"),
        validator.clone(),
        0,
        reporter_cfg,
    );

    let validator_idx = participants
        .iter()
        .position(|participant| participant == &validator)
        .expect("validator must be in participants");
    let app_cfg = application::Config::<Sha256, _> {
        relay,
        me: validator.clone(),
        propose_latency: (10.0, 5.0),
        verify_latency: (10.0, 5.0),
        certify_latency: (10.0, 5.0),
        should_certify: certify.into_certifier(validator_idx),
    };
    let (actor, application) = application::Application::new(context.child("application"), app_cfg);
    actor.start();
    let automaton = RecordingAutomaton::new(
        context.child("automaton_recorder"),
        application.clone(),
        reporter.audit(),
    );

    let (vote_sender, vote_receiver) = pending;
    let (certificate_sender, certificate_receiver) = recovered;
    let (resolver_sender, resolver_receiver) = resolver;
    let engine_cfg = config::Config {
        blocker: oracle.control(validator.clone()),
        scheme,
        elector,
        automaton,
        relay: application,
        reporter: wiring.wire(reporter.clone()),
        partition: validator.to_string(),
        mailbox_size,
        epoch: Epoch::new(EPOCH),
        floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(EPOCH))),
        leader_timeout,
        certification_timeout,
        timeout_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        view_retention: Delta::new(10),
        skip_timeout: Duration::from_secs(11),
        fetch_concurrent,
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
        forwarding,
    };
    Engine::new(context.child("engine"), engine_cfg).start(
        (vote_sender, vote_receiver),
        (certificate_sender, certificate_receiver),
        (resolver_sender, resolver_receiver),
    );

    reporter
}

/// Build an honest validator (application, reporter, engine) and RETAIN its task
/// handles in a [`ManagedValidator`], instead of dropping them like
/// [`spawn_honest_validator`]. The storage partition is `validator.to_string()`,
/// matching the historical behavior of the dropped-handle path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_validator<
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
    mailbox_size: NonZeroUsize,
    fetch_concurrent: NonZeroUsize,
    forwarding: ForwardingPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> ManagedValidator<P, EC>
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
    let partition = validator.to_string();
    build_validator_with_reporter::<P, EC, _, _, _, _, _, _>(
        None,
        context,
        oracle,
        participants,
        scheme,
        validator,
        elector,
        relay,
        leader_timeout,
        certification_timeout,
        mailbox_size,
        fetch_concurrent,
        forwarding,
        partition,
        pending,
        recovered,
        resolver,
        certify,
        wiring,
    )
}

/// [`build_validator`] with an explicit reporter and storage partition. When
/// `existing` is `Some`, that reporter instance is reused (rather than a fresh
/// one created) so a durable restart RETAINS the pre-crash safety history whose
/// Arc-backed maps survived the abort. The public build paths pass `None` and the
/// default `validator.to_string()` partition; a durable restart passes the
/// crashed validator's reporter and its unchanged partition.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_validator_with_reporter<
    P,
    EC,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    existing: Option<reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>>,
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: EC,
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    fetch_concurrent: NonZeroUsize,
    forwarding: ForwardingPolicy,
    partition: String,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> ManagedValidator<P, EC>
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
    let reporter = match existing {
        Some(reporter) => reporter,
        None => {
            let reporter_cfg = reporter::Config {
                participants: participants.try_into().expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: elector.clone(),
            };
            reporter::Reporter::new(context.child("reporter"), reporter_cfg)
        }
    };

    let (vote_sender, vote_receiver) = pending;
    let (certificate_sender, certificate_receiver) = recovered;
    let (resolver_sender, resolver_receiver) = resolver;

    let validator_idx = participants
        .iter()
        .position(|p| p == &validator)
        .expect("validator must be in participants");
    let app_cfg = application::Config::<Sha256, _> {
        relay,
        me: validator.clone(),
        propose_latency: (10.0, 5.0),
        verify_latency: (10.0, 5.0),
        certify_latency: (10.0, 5.0),
        should_certify: certify.into_certifier(validator_idx),
    };
    let (actor, application) = application::Application::new(context.child("application"), app_cfg);
    let app_handle = actor.start();

    let blocker = oracle.control(validator.clone());
    let stored_scheme = scheme.clone();
    let engine_cfg = config::Config {
        blocker,
        scheme,
        elector,
        automaton: application.clone(),
        relay: application.clone(),
        reporter: wiring.wire(reporter.clone()),
        partition: partition.clone(),
        mailbox_size,
        epoch: Epoch::new(EPOCH),
        floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(EPOCH))),
        leader_timeout,
        certification_timeout,
        timeout_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        view_retention: Delta::new(10),
        skip_timeout: Duration::from_secs(11),
        fetch_concurrent,
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
        forwarding,
    };
    let engine = Engine::new(context.child("engine"), engine_cfg);
    let engine_handle = engine.start(
        (vote_sender, vote_receiver),
        (certificate_sender, certificate_receiver),
        (resolver_sender, resolver_receiver),
    );

    ManagedValidator {
        idx: validator_idx,
        validator,
        scheme: stored_scheme,
        partition,
        generation: 0,
        reporter,
        app_handle: Some(app_handle),
        engine_handle: Some(engine_handle),
        lifecycle: ValidatorLifecycle::Running,
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_honest_validator_in_faulty_messaging<P: simplex::Simplex>(
    context: deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    term_length: TermLength,
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    byzantine_router: crate::network::Router<PublicKeyOf<P>, deterministic::Context>,
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    fetch_concurrent: NonZeroUsize,
    forwarding: ForwardingPolicy,
    channels: NetworkChannels<PublicKeyOf<P>>,
    certify: CertifyChoice,
    wiring: ReporterWiring,
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
        P::elector(term_length),
        relay,
        leader_timeout,
        certification_timeout,
        mailbox_size,
        fetch_concurrent,
        forwarding,
        (vote_sender, vote_receiver),
        (certificate_sender, certificate_receiver),
        (resolver_sender, resolver_receiver),
        certify,
        wiring,
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

async fn reporter_view_stream<K, R>(
    context: &deterministic::Context,
    reporters: &mut [(K, R)],
) -> Option<(u64, mpsc::UnboundedReceiver<u64>)>
where
    R: Monitor<Index = View>,
{
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

async fn spawn_network_fault_scheduler<P, R>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    participants: &[PublicKeyOf<P>],
    reporters: &mut [(PublicKeyOf<P>, R)],
    partition: Partition,
    required_containers: u64,
    initial_partition: Option<SetPartition>,
) where
    P: simplex::Simplex,
    R: Monitor<Index = View>,
{
    let Some(schedule) = partition.schedule() else {
        return;
    };
    if schedule.is_empty() || reporters.is_empty() {
        return;
    }
    let Some((mut finalized_view, mut view_rx)) = reporter_view_stream(context, reporters).await
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
async fn spawn_messaging_fault_scheduler<P, R>(
    context: &deterministic::Context,
    reporters: &mut [(PublicKeyOf<P>, R)],
    schedule: Vec<(View, u8)>,
    required_containers: u64,
    drop_rate: network::DropRateCell,
    initial_rate: u8,
) where
    P: simplex::Simplex,
    R: Monitor<Index = View>,
{
    if schedule.is_empty() || reporters.is_empty() {
        return;
    }
    let Some((mut finalized_view, mut view_rx)) = reporter_view_stream(context, reporters).await
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
        StrategyChoice::HeaderScope {
            fault_rounds,
            fault_rounds_bound,
            mutation,
        } => HeaderScope {
            fault_rounds,
            fault_rounds_bound,
            mutation,
        }
        .network_faults(required_containers, rng),
        StrategyChoice::SplitHeader {
            fault_rounds,
            fault_rounds_bound,
        } => SplitHeader {
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
        StrategyChoice::HeaderScope {
            fault_rounds,
            fault_rounds_bound,
            mutation,
        } => HeaderScope {
            fault_rounds,
            fault_rounds_bound,
            mutation,
        }
        .messaging_faults(required_containers, rng),
        StrategyChoice::SplitHeader {
            fault_rounds,
            fault_rounds_bound,
        } => SplitHeader {
            fault_rounds,
            fault_rounds_bound,
        }
        .messaging_faults(required_containers, rng),
    }
}

/// The trace-collection stack: a shared registry with a filtered
/// [CollectingLayer] over the given storage.
fn warn_trace_dispatch(trace_store: TraceStorage) -> Dispatch {
    let collecting_layer = CollectingLayer::new(trace_store).with_filter(filter_fn(|metadata| {
        (metadata.is_span()
            && metadata
                .target()
                .contains("commonware_consensus::simplex::actors::"))
            || (metadata.is_event() && *metadata.level() == Level::WARN)
            || (metadata.is_event()
                && *metadata.level() == Level::DEBUG
                && (metadata
                    .target()
                    .contains("commonware_consensus::simplex::actors::resolver")
                    || metadata
                        .target()
                        .contains("commonware_consensus::simplex::actors::voter")))
    }));
    Dispatch::new(tracing_subscriber::registry().with(collecting_layer))
}

/// Collect WARN events from the whole protocol run and feed bounded tokens into
/// state coverage.
///
/// Reporter-derived state is filtered to honest reporters in twins modes because
/// those tokens model protocol-state correctness. WARN events intentionally stay
/// whole-network: tracing events do not carry the emitting validator identity
/// without adding protocol instrumentation, and adversarial twin engines hitting
/// rejection paths is useful reachability feedback.
///
/// The collector dispatch is passed to `run` so paths that install per-node
/// subscribers (happens-before) can tee validator-task traces back into it.
fn run_with_warn_trace_collection<T>(run: impl FnOnce(&Dispatch) -> T) -> T {
    let trace_store = TraceStorage::default();
    let dispatch = warn_trace_dispatch(trace_store.clone());

    let output = dispatcher::with_default(&dispatch, || run(&dispatch));

    let events = trace_store.get_all();
    state_cov::observe_trace_events(&events);
    output
}

/// The consensus channel a [`SniffingReceiver`] decodes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SniffChannel {
    Vote,
    Certificate,
    Resolver,
}

/// Decode a sniffed payload into its wire-arrival event (view, kind). Vote and
/// certificate channels carry the message directly; the resolver channel frames
/// it, with backfill responses delivering certificates (requests and errors
/// carry none and record nothing). `None` when the payload does not decode.
fn sniff_event<P: simplex::Simplex>(
    channel: SniffChannel,
    payload: &IoBuf,
    cert_cfg: &CertCfgOf<P>,
) -> Option<(u64, happens_before::EventKind)> {
    let cert_event = |cert: Certificate<P::Scheme, Sha256Digest>| {
        let kind = match &cert {
            Certificate::Notarization(_) => happens_before::EventKind::ReceiveNotarization,
            Certificate::Nullification(_) => happens_before::EventKind::ReceiveNullification,
            Certificate::Finalization(_) => happens_before::EventKind::ReceiveFinalization,
        };
        (cert.view().get(), kind)
    };
    match channel {
        SniffChannel::Vote => Vote::<P::Scheme, Sha256Digest>::decode(payload.clone())
            .ok()
            .map(|vote| {
                let kind = match &vote {
                    Vote::Notarize(_) => happens_before::EventKind::ReceiveNotarize,
                    Vote::Nullify(_) => happens_before::EventKind::ReceiveNullify,
                    Vote::Finalize(_) => happens_before::EventKind::ReceiveFinalize,
                };
                (vote.view().get(), kind)
            }),
        SniffChannel::Certificate => {
            Certificate::<P::Scheme, Sha256Digest>::decode_cfg(payload.clone(), cert_cfg)
                .ok()
                .map(cert_event)
        }
        SniffChannel::Resolver => match ResolverMessage::<U64>::decode(payload.clone())
            .ok()?
            .payload
        {
            ResolverPayload::Response(bytes) => {
                Certificate::<P::Scheme, Sha256Digest>::decode_cfg(bytes, cert_cfg)
                    .ok()
                    .map(cert_event)
            }
            ResolverPayload::Request(_) | ResolverPayload::Error => None,
        },
    }
}

/// p2p-boundary capture: wraps a validator's vote, certificate, or resolver
/// receiver, decodes each incoming message and records the wire RECEIVE into the
/// happens-before log, attributed to the receiving node and tagged with the
/// real sender's node id (resolved against the participant set, so the
/// send-before-receive merge uses that exact sender's history). This is the
/// arrival of a message, distinct from the node later PROCESSING it (a separate
/// tracing event): a message can arrive and be dropped without being processed.
/// Transparent (forwards the message unchanged); a `None` sink is a zero-decode
/// pass-through for runs without happens-before capture.
pub(crate) struct SniffingReceiver<P: simplex::Simplex, R> {
    inner: R,
    channel: SniffChannel,
    cert_cfg: CertCfgOf<P>,
    sink: SniffSink<P>,
    _p: std::marker::PhantomData<fn() -> P>,
}

impl<P: simplex::Simplex, R> SniffingReceiver<P, R> {
    pub(crate) fn new(
        inner: R,
        channel: SniffChannel,
        cert_cfg: CertCfgOf<P>,
        sink: SniffSink<P>,
    ) -> Self {
        Self {
            inner,
            channel,
            cert_cfg,
            sink,
            _p: std::marker::PhantomData,
        }
    }
}

impl<P: simplex::Simplex, R> fmt::Debug for SniffingReceiver<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniffingReceiver").finish()
    }
}

impl<P, R> commonware_p2p::Receiver for SniffingReceiver<P, R>
where
    P: simplex::Simplex,
    R: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    type Error = R::Error;
    type PublicKey = PublicKeyOf<P>;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let (sender, payload) = self.inner.recv().await?;
        if let Some(sniff) = &self.sink
            && let Some((view, kind)) = sniff_event::<P>(self.channel, &payload, &self.cert_cfg)
        {
            let from = sniff
                .peers
                .iter()
                .position(|p| p == &sender)
                .map(|i| i as u32)
                .filter(|i| !sniff.ambiguous.contains(i));
            sniff.log.record(happens_before::Event {
                node: sniff.node,
                view,
                kind,
                sender: from,
            });
        }
        Ok((sender, payload))
    }
}

fn run_standard_once<P: simplex::Simplex>(
    mut input: FuzzInput,
    state_coverage: bool,
    collect_audit: bool,
    happens_before: bool,
    warn_dispatch: Option<Dispatch>,
) -> Option<RunAudit> {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let hb_log = happens_before.then(happens_before::capture::EventLog::new);

    executor.start(move |mut context| async move {
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

        let relay = Arc::new(relay::Relay::<Sha256Digest, _>::new());
        let mut reporters = Vec::new();
        let config = input.configuration;
        let term_length = P::effective_term_length(input.term_length);

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
        let peers: Arc<[PublicKeyOf<P>]> = participants.clone().into();
        let ambiguous: Arc<[u32]> = Vec::new().into();
        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            // p2p-boundary sniffing: capture wire arrivals of votes,
            // certificates, and resolver backfill responses (distinct from the
            // node processing them, which the tracing source records).
            // Pass-through when not capturing.
            let pending = {
                let (vote_sender, vote_receiver) = pending;
                let sink = sniff_sink(&hb_log, i as u32, &peers, &ambiguous);
                let cfg = schemes[i].certificate_codec_config();
                (
                    vote_sender,
                    SniffingReceiver::<P, _>::new(vote_receiver, SniffChannel::Vote, cfg, sink),
                )
            };
            let recovered = {
                let (cert_sender, cert_receiver) = recovered;
                let sink = sniff_sink(&hb_log, i as u32, &peers, &ambiguous);
                let cfg = schemes[i].certificate_codec_config();
                (
                    cert_sender,
                    SniffingReceiver::<P, _>::new(
                        cert_receiver,
                        SniffChannel::Certificate,
                        cfg,
                        sink,
                    ),
                )
            };
            let resolver = {
                let (backfill_sender, backfill_receiver) = resolver;
                let sink = sniff_sink(&hb_log, i as u32, &peers, &ambiguous);
                let cfg = schemes[i].certificate_codec_config();
                (
                    backfill_sender,
                    SniffingReceiver::<P, _>::new(
                        backfill_receiver,
                        SniffChannel::Resolver,
                        cfg,
                        sink,
                    ),
                )
            };
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let spawn = || {
                spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    schemes[i].clone(),
                    validator.clone(),
                    P::elector(term_length),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.fetch_concurrent,
                    input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    input.certify,
                    input.reporting,
                )
            };
            // Dispatch propagation: every task the engine spawns inherits this
            // per-node subscriber, so its tracing events are attributed to node
            // `i`. The subscriber shadows the whole-run trace collector for
            // those tasks, so tee it back in when one is installed.
            let reporter = match &hb_log {
                Some(log) => {
                    let mut subscriber =
                        happens_before::capture::NodeSubscriber::new(i as u32, log.clone());
                    if let Some(inner) = &warn_dispatch {
                        subscriber = subscriber.with_inner(inner.clone());
                    }
                    let dispatch = Dispatch::new(subscriber);
                    dispatcher::with_default(&dispatch, spawn)
                }
                None => spawn(),
            };
            reporters.push((validator, reporter));
        }

        spawn_network_fault_scheduler::<P, _>(
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
            // Feedback stays behind the validity gate (like protocol-state
            // coverage): invalid configurations never reach the invariant
            // checks, so their interleavings must not be retained as novel.
            let hb_summary = hb_log.as_ref().map(|log| log.summary());
            if let Some(summary) = &hb_summary {
                let mut tokens = summary.tokens();
                if let Some(bucket) = summary.dispersion_bucket() {
                    tokens.insert(format!("hb:dispersion={bucket}"));
                }
                tokens.extend(summary.lsh_tokens());
                state_cov::observe_tokens(tokens);
            }
            let reporter_only: Vec<_> = reporters.iter().map(|(_, r)| r.clone()).collect();
            invariants::check_no_invalid_reports_if_no_faults(config.faults, &reporter_only);
            invariants::check_vote_invariants(
                config.faults as usize,
                P::elector(term_length),
                Epoch::new(EPOCH),
                term_length,
                &reporter_only,
            );
            let reporter_states = (state_coverage || collect_audit)
                .then(|| state_cov::encode_reporter_states(&reporter_only, config.n as usize));
            if state_coverage {
                let metrics = context.encode();
                state_cov::observe_with_metrics(
                    reporter_states
                        .as_ref()
                        .expect("state coverage needs reporter states"),
                    &metrics,
                );
            }
            let audit = collect_audit.then(|| RunAudit {
                auditor_state: context.auditor().state(),
                reporter_states: reporter_states.unwrap_or_default(),
                happens_before: hb_summary,
            });
            let states = invariants::extract(reporter_only);
            invariants::check::<P>(term_length, states);
            audit
        } else {
            None
        }
    })
}

/// Run the Standard harness with append-only Simplex activity and automaton
/// recording enabled.
///
/// This path exists only for the dedicated Standard audit fuzz targets. The
/// shared [`run_standard_once`] path continues to use the consensus mock
/// reporter and application automaton directly.
fn run_audited_standard_once<P: simplex::Simplex>(mut input: FuzzInput) -> (bool, bool) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(move |mut context| async move {
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

        let relay = Arc::new(relay::Relay::<Sha256Digest, _>::new());
        let mut reporters = Vec::new();
        let config = input.configuration;
        let term_length = P::effective_term_length(input.term_length);

        for i in 0..config.faults as usize {
            let validator = participants[i].clone();
            let channels = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            if matches!(input.certify, CertifyChoice::RejectView { .. }) {
                // A Byzantine participant may behave correctly. For the audit
                // rejection campaign, run its normal engine so the designated
                // Byzantine-led view reliably has a well-formed proposal. Its
                // application always certifies its own proposal, while all
                // correct applications consistently reject it. Its raw reporter
                // is intentionally excluded from the correct audit set below.
                let (pending, recovered, resolver) = channels;
                let _ = spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                    ctx,
                    &oracle,
                    &participants,
                    schemes[i].clone(),
                    validator,
                    P::elector(term_length),
                    relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                    input.mailbox_size,
                    input.fetch_concurrent,
                    input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    CertifyChoice::Always,
                    ReporterWiring::Solo,
                );
            } else {
                spawn_disrupter::<P>(ctx, schemes[i].clone(), &input, channels);
            }
        }

        for i in (config.faults as usize)..(config.n as usize) {
            let validator = participants[i].clone();
            let (pending, recovered, resolver) = registrations.remove(&validator).unwrap();
            let ctx = context
                .child("validator")
                .with_attribute("public_key", &validator);
            let reporter = spawn_audited_validator::<P, _, _, _, _, _, _, _>(
                ctx,
                &oracle,
                &participants,
                schemes[i].clone(),
                validator.clone(),
                P::elector(term_length),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                input.mailbox_size,
                input.fetch_concurrent,
                input.forwarding,
                pending,
                recovered,
                resolver,
                input.certify,
                input.reporting,
            );
            reporters.push((validator, reporter));
        }

        spawn_network_fault_scheduler::<P, _>(
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

        if !config.is_valid() {
            return (false, false);
        }

        let reporter_only: Vec<_> = reporters
            .into_iter()
            .map(|(_, reporter)| reporter)
            .collect();
        let summary_reporters = summaries(&reporter_only);
        let rejected_certification_observed = reporter_only.iter().any(|reporter| {
            reporter.audit().events().iter().any(|recorded| {
                matches!(
                    &recorded.event,
                    simplex_audit::Event::Automaton(
                        simplex_audit::AutomatonEvent::CertifyCompleted {
                            outcome: simplex_audit::Completion::Returned(false),
                            ..
                        }
                    )
                )
            })
        });
        invariants::check_no_invalid_reports_if_no_faults(config.faults, &summary_reporters);
        invariants::check_vote_invariants(
            config.faults as usize,
            P::elector(term_length),
            Epoch::new(EPOCH),
            term_length,
            &summary_reporters,
        );
        invariants::check::<P>(term_length, reporter_only.as_slice());
        (true, rejected_certification_observed)
    })
}

fn run<P: simplex::Simplex>(input: FuzzInput, state_coverage: bool, happens_before: bool) {
    if state_coverage || happens_before {
        state_cov::reset();
    }
    if happens_before {
        if state_coverage {
            // Per-node subscribers shadow the collector for validator tasks, so
            // its dispatch is teed through them to keep trace-event tokens fed.
            let _ = run_with_warn_trace_collection(|dispatch| {
                run_standard_once::<P>(input, true, false, true, Some(dispatch.clone()))
            });
        } else {
            let _ = run_standard_once::<P>(input, false, false, true, None);
        }
    } else if state_coverage {
        let _ = run_with_warn_trace_collection(|_| {
            run_standard_once::<P>(input, true, false, false, None)
        });
    } else {
        let _ = run_standard_once::<P>(input, false, false, false, None);
    }
}

fn run_with_faulty_messaging<P: simplex::Simplex>(mut input: FuzzInput) {
    // FaultyMessaging is a transport-layer fault axis; topology is always fully
    // connected. Network-layer fault axes (`Static` / `Adaptive` partitions,
    // degraded link) are explicitly disabled here so the only adversarial
    // delivery effects come from the per-view messaging schedule below.
    input.partition = Partition::Connected;
    input.configuration = N4F1C3;
    input.degraded_network = false;
    // Three honest certifiers are exactly the finalize quorum here.
    input.certify = CertifyChoice::Always;

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

        let relay = Arc::new(relay::Relay::<Sha256Digest, _>::new());
        let mut reporters = Vec::new();
        let config = input.configuration;
        let term_length = P::effective_term_length(input.term_length);

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
                term_length,
                schemes[i].clone(),
                validator.clone(),
                byzantine_router.clone(),
                relay.clone(),
                Duration::from_secs(1),
                Duration::from_secs(2),
                input.mailbox_size,
                input.fetch_concurrent,
                input.forwarding,
                channels,
                input.certify,
                input.reporting,
            );
            reporters.push((validator, reporter));
        }

        // Spawn a per-view messaging-fault scheduler that updates the shared
        // drop-rate cell as the reference reporter advances.
        spawn_messaging_fault_scheduler::<P, _>(
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
            invariants::check_no_invalid_reports_if_no_faults(config.faults, &reporter_only);
            invariants::check_vote_invariants(
                config.faults as usize,
                P::elector(term_length),
                Epoch::new(EPOCH),
                term_length,
                &reporter_only,
            );
            let states = invariants::extract(reporter_only);
            invariants::check::<P>(term_length, states);
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

pub(crate) type TwinsElector<P> = twins::Elector<<P as simplex::Simplex>::Elector>;

/// Observation retained for one Twins engine. Existing Twins targets use the
/// summary variant; dedicated audit targets use the recording variant only for
/// correct engines.
enum TwinsReporter<P>
where
    P: simplex::Simplex,
{
    Summary(reporter::Reporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest>),
    Recording(RecordingReporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest>),
}

impl<P> Clone for TwinsReporter<P>
where
    P: simplex::Simplex,
{
    fn clone(&self) -> Self {
        match self {
            Self::Summary(reporter) => Self::Summary(reporter.clone()),
            Self::Recording(reporter) => Self::Recording(reporter.clone()),
        }
    }
}

impl<P> TwinsReporter<P>
where
    P: simplex::Simplex,
{
    fn summary(
        &self,
    ) -> reporter::Reporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest> {
        match self {
            Self::Summary(reporter) => reporter.clone(),
            Self::Recording(reporter) => reporter.inner().clone(),
        }
    }

    fn recording(
        &self,
    ) -> Option<RecordingReporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest>>
    {
        match self {
            Self::Summary(_) => None,
            Self::Recording(reporter) => Some(reporter.clone()),
        }
    }

    async fn subscribe(&mut self) -> (View, Receiver<View>) {
        match self {
            Self::Summary(reporter) => reporter.subscribe().await,
            Self::Recording(reporter) => reporter.subscribe().await,
        }
    }
}

/// Network and stack state prepared by a [`TwinsBackend`].
pub(crate) struct TwinsSetup<P: simplex::Simplex, S> {
    pub(crate) oracle: Oracle<PublicKeyOf<P>, deterministic::Context>,
    pub(crate) participants: Vec<PublicKeyOf<P>>,
    pub(crate) schemes: Vec<P::Scheme>,
    pub(crate) registrations: HashMap<PublicKeyOf<P>, NetworkChannels<PublicKeyOf<P>>>,
    pub(crate) state: S,
}

/// One selected Twins scenario plus backend-specific case metadata.
pub(crate) struct TwinsCase<C> {
    pub(crate) scenario: twins::Scenario,
    pub(crate) compromised: Vec<usize>,
    pub(crate) data: C,
}

/// Shared topology passed to every stack-specific Twins hook.
pub(crate) struct TwinsTopology<P: simplex::Simplex, C> {
    pub(crate) scenario: twins::Scenario,
    pub(crate) compromised: HashSet<usize>,
    pub(crate) elector: TwinsElector<P>,
    pub(crate) term_length: TermLength,
    #[cfg_attr(not(feature = "mocks"), allow(dead_code))]
    pub(crate) data: C,
}

/// Configuration for a secondary twin implemented by the existing Disrupter.
#[derive(Clone, Copy)]
pub(crate) struct TwinsDisrupter {
    pub(crate) strategy: StrategyChoice,
    pub(crate) required_containers: u64,
    pub(crate) epoch: Epoch,
}

/// Stack-specific hooks for the shared Twins topology driver.
///
/// The driver owns scenario generation, compromised-node iteration, channel
/// splitting/routing, twin role dispatch, Disrupter startup, and honest-node
/// iteration. A backend owns its network/validator stack, engine construction,
/// liveness observation, and final invariants.
pub(crate) trait TwinsBackend<P: simplex::Simplex> {
    type State;
    type Case;

    fn setup(
        &mut self,
        context: &mut deterministic::Context,
    ) -> impl std::future::Future<Output = TwinsSetup<P, Self::State>> + Send;

    fn term_length(&self) -> TermLength;

    /// Select the framework whose cases the shared driver will generate.
    fn framework(
        &mut self,
        context: &mut deterministic::Context,
        participants: usize,
    ) -> twins::Framework;

    /// Select one generated case and attach backend-specific metadata.
    fn select_case(
        &mut self,
        context: &mut deterministic::Context,
        participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>>;

    #[allow(clippy::too_many_arguments)]
    fn spawn_primary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    );

    /// Return a Disrupter configuration when the shared driver should own the
    /// secondary half. `None` delegates secondary engine construction to the
    /// backend.
    fn disrupter(&self) -> Option<TwinsDisrupter>;

    #[allow(clippy::too_many_arguments)]
    fn spawn_secondary(
        &mut self,
        _context: deterministic::Context,
        _state: &mut Self::State,
        _oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        _participants: &Arc<[PublicKeyOf<P>]>,
        _scheme: P::Scheme,
        _validator: PublicKeyOf<P>,
        _idx: usize,
        _topology: &TwinsTopology<P, Self::Case>,
        _vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        _certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        _resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) {
        panic!("backend secondary hook called while configured for a Disrupter");
    }

    /// Called after every twin pair is started and before honest construction.
    fn finish_twins(&mut self, _state: &mut Self::State, _topology: &TwinsTopology<P, Self::Case>) {
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_honest(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        channels: NetworkChannels<PublicKeyOf<P>>,
    );

    fn observe_liveness(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        prefix_end: View,
    ) -> impl std::future::Future<Output = ()> + Send;

    fn check_invariants(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        topology: &TwinsTopology<P, Self::Case>,
    );
}

/// Run one Twins scenario over a stack supplied by `backend`.
pub(crate) async fn run_twins_with_backend<P, B>(
    context: &mut deterministic::Context,
    backend: &mut B,
) where
    P: simplex::Simplex,
    B: TwinsBackend<P>,
{
    let mut setup = backend.setup(context).await;
    let participants: Arc<[PublicKeyOf<P>]> = setup.participants.into();
    let term_length = backend.term_length();
    let framework = backend.framework(context, participants.len());
    let cases = twins::cases(context, framework);
    let Some(case) = backend.select_case(context, participants.as_ref(), cases) else {
        return;
    };
    assert!(
        !case.compromised.is_empty(),
        "Twins case must compromise at least one participant"
    );
    assert!(
        case.compromised.iter().all(|idx| *idx < participants.len()),
        "Twins case contains a participant index outside the validator set"
    );
    let compromised = case.compromised.iter().copied().collect::<HashSet<_>>();
    let topology = TwinsTopology {
        elector: twins::Elector::new(P::elector(term_length), &case.scenario, participants.len()),
        scenario: case.scenario,
        compromised,
        term_length,
        data: case.data,
    };

    for idx in case.compromised {
        let validator = participants[idx].clone();
        let node_context = context.child("validator").with_attribute("index", idx);
        let scheme = setup.schemes[idx].clone();
        let (vote_network, certificate_network, resolver_network) = setup
            .registrations
            .remove(&validator)
            .expect("twin validator should be registered");
        let (vote_sender, vote_receiver) = vote_network;
        let (certificate_sender, certificate_receiver) = certificate_network;
        let (resolver_sender, resolver_receiver) = resolver_network;

        let (vote_sender_primary, vote_sender_secondary) =
            vote_sender.split_with(twins_network::vote_forwarder::<P>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
            ));
        let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
            node_context.child("vote_split"),
            twins_network::vote_router::<P>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
            ),
        );
        let (certificate_sender_primary, certificate_sender_secondary) = certificate_sender
            .split_with(twins_network::certificate_forwarder::<P>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
                scheme.clone(),
            ));
        let (certificate_receiver_primary, certificate_receiver_secondary) = certificate_receiver
            .split_with(
                node_context.child("certificate_split"),
                twins_network::certificate_router::<P>(
                    participants.clone(),
                    topology.scenario.clone(),
                    term_length,
                    scheme.clone(),
                ),
            );
        let (resolver_sender_primary, resolver_sender_secondary) =
            resolver_sender.split_with(twins_network::resolver_forwarder::<P>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
                scheme.clone(),
            ));
        let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
            .split_with(
                node_context.child("resolver_split"),
                twins_network::resolver_router::<P>(
                    participants.clone(),
                    topology.scenario.clone(),
                    term_length,
                    scheme.clone(),
                ),
            );

        backend.spawn_primary(
            node_context.child("primary"),
            &mut setup.state,
            &setup.oracle,
            &participants,
            scheme.clone(),
            validator.clone(),
            idx,
            &topology,
            (vote_sender_primary, vote_receiver_primary),
            (certificate_sender_primary, certificate_receiver_primary),
            (resolver_sender_primary, resolver_receiver_primary),
        );
        if let Some(disrupter) = backend.disrupter() {
            start_disrupter_with_epoch::<P>(
                node_context.child("secondary"),
                scheme,
                &disrupter.strategy,
                disrupter.required_containers,
                disrupter.epoch,
                (vote_sender_secondary, vote_receiver_secondary),
                (certificate_sender_secondary, certificate_receiver_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        } else {
            backend.spawn_secondary(
                node_context.child("secondary"),
                &mut setup.state,
                &setup.oracle,
                &participants,
                scheme,
                validator,
                idx,
                &topology,
                (vote_sender_secondary, vote_receiver_secondary),
                (certificate_sender_secondary, certificate_receiver_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        }
    }

    backend.finish_twins(&mut setup.state, &topology);
    for (idx, validator) in participants.iter().enumerate() {
        if topology.compromised.contains(&idx) {
            continue;
        }
        let channels = setup
            .registrations
            .remove(validator)
            .expect("honest validator should be registered");
        backend.spawn_honest(
            context.child("validator").with_attribute("index", idx),
            &mut setup.state,
            &setup.oracle,
            &participants,
            setup.schemes[idx].clone(),
            validator.clone(),
            idx,
            &topology,
            channels,
        );
    }

    let prefix_end =
        View::new(topology.scenario.rounds().len() as u64 * topology.term_length.get());
    backend
        .observe_liveness(context, &mut setup.state, prefix_end)
        .await;
    backend.check_invariants(context, &mut setup.state, &topology);
}

fn run_with_twins_mutator<P: simplex::Simplex>(
    input: FuzzInput,
    state_coverage: bool,
    happens_before: bool,
) {
    let _ = run_twins::<P>(
        input,
        TwinsRole::Mutator,
        state_coverage,
        happens_before,
        false,
    );
}

fn run_with_twins_campaign<P: simplex::Simplex>(
    input: FuzzInput,
    state_coverage: bool,
    happens_before: bool,
) {
    let _ = run_twins::<P>(
        input,
        TwinsRole::Campaign,
        state_coverage,
        happens_before,
        false,
    );
}

struct MockTwinsBackend<P: simplex::Simplex> {
    input: FuzzInput,
    role: TwinsRole,
    state_coverage: bool,
    record_audit: bool,
    hb_log: Option<happens_before::capture::EventLog>,
    warn_dispatch: Option<Dispatch>,
    _marker: std::marker::PhantomData<fn() -> P>,
}

struct MockTwinsState<P: simplex::Simplex> {
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    reporters: Vec<TwinsReporter<P>>,
    twin_observers: Vec<TwinsReporter<P>>,
    honest_start: usize,
}

impl<P: simplex::Simplex> MockTwinsBackend<P> {
    fn new(
        input: FuzzInput,
        role: TwinsRole,
        state_coverage: bool,
        record_audit: bool,
        hb_log: Option<happens_before::capture::EventLog>,
        warn_dispatch: Option<Dispatch>,
    ) -> Self {
        Self {
            input,
            role,
            state_coverage,
            record_audit,
            hb_log,
            warn_dispatch,
            _marker: std::marker::PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_twin_engine(
        &self,
        context: deterministic::Context,
        state: &MockTwinsState<P>,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, ()>,
        partition: String,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) -> reporter::Reporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest> {
        let reporter_cfg = reporter::Config {
            participants: participants
                .as_ref()
                .try_into()
                .expect("public keys are unique"),
            scheme: scheme.clone(),
            elector: topology.elector.clone(),
        };
        let reporter = reporter::Reporter::new(context.child("reporter"), reporter_cfg);
        let app_cfg = application::Config::<Sha256, _> {
            relay: state.relay.clone(),
            me: validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: application::Certifier::Always,
        };
        let (actor, application) =
            application::Application::new(context.child("application"), app_cfg);
        actor.start();
        let engine = Engine::new(
            context.child("engine"),
            config::Config {
                blocker: oracle.control(validator),
                scheme,
                elector: topology.elector.clone(),
                automaton: application.clone(),
                relay: application,
                reporter: reporter.clone(),
                partition,
                mailbox_size: self.input.mailbox_size,
                epoch: Epoch::new(EPOCH),
                floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(EPOCH))),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_millis(1_500),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                view_retention: Delta::new(10),
                skip_timeout: Duration::from_secs(11),
                fetch_concurrent: self.input.fetch_concurrent,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: self.input.forwarding,
            },
        );
        engine.start(vote, certificate, resolver);
        let _ = idx;
        reporter
    }
}

impl<P: simplex::Simplex> TwinsBackend<P> for MockTwinsBackend<P> {
    type State = MockTwinsState<P>;
    type Case = ();

    async fn setup(&mut self, context: &mut deterministic::Context) -> TwinsSetup<P, Self::State> {
        let (mut oracle, participants, schemes, registrations) =
            setup_network::<P>(context, &self.input).await;
        link_peers(
            &mut oracle,
            &participants,
            Action::Update(Link {
                latency: Duration::from_millis(500),
                jitter: Duration::from_millis(500),
                success_rate: 1.0,
            }),
            self.input.partition.set_partition(),
        )
        .await;
        TwinsSetup {
            oracle,
            participants,
            schemes,
            registrations,
            state: MockTwinsState {
                relay: Arc::new(relay::Relay::new()),
                reporters: Vec::new(),
                twin_observers: Vec::new(),
                honest_start: 0,
            },
        }
    }

    fn term_length(&self) -> TermLength {
        P::effective_term_length(self.input.term_length)
    }

    fn framework(
        &mut self,
        context: &mut deterministic::Context,
        participants: usize,
    ) -> twins::Framework {
        let mode = if rand::RngExt::random_bool(context, 0.5) {
            twins::Mode::Sampled
        } else {
            twins::Mode::Sustained
        };
        twins::Framework {
            participants,
            faults: self.input.configuration.faults as usize,
            rounds: (self.input.required_containers as usize).clamp(1, 8),
            mode,
            max_cases: 16,
        }
    }

    fn select_case(
        &mut self,
        context: &mut deterministic::Context,
        _participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>> {
        if cases.is_empty() {
            return None;
        }
        let case_idx = rand::RngExt::random_range(context, 0..cases.len());
        let case = cases.into_iter().nth(case_idx)?;
        Some(TwinsCase {
            scenario: case.scenario,
            compromised: case.compromised,
            data: (),
        })
    }

    fn spawn_primary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) {
        let reporter = self.spawn_twin_engine(
            context,
            state,
            oracle,
            participants,
            scheme,
            validator,
            idx,
            topology,
            format!("twin_{idx}_primary"),
            vote,
            certificate,
            resolver,
        );
        match self.role {
            TwinsRole::Campaign => state.reporters.push(TwinsReporter::Summary(reporter)),
            TwinsRole::Mutator => state.twin_observers.push(TwinsReporter::Summary(reporter)),
        }
    }

    fn disrupter(&self) -> Option<TwinsDisrupter> {
        (matches!(self.role, TwinsRole::Mutator)).then_some(TwinsDisrupter {
            strategy: self.input.strategy,
            required_containers: self.input.required_containers,
            epoch: Epoch::new(EPOCH),
        })
    }

    fn spawn_secondary(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        vote: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        certificate: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
        resolver: (
            impl commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
            impl commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
        ),
    ) {
        assert!(
            matches!(self.role, TwinsRole::Campaign),
            "mock secondary engine is only used by TwinsCampaign"
        );
        let reporter = self.spawn_twin_engine(
            context,
            state,
            oracle,
            participants,
            scheme,
            validator,
            idx,
            topology,
            format!("twin_{idx}_secondary"),
            vote,
            certificate,
            resolver,
        );
        state.reporters.push(TwinsReporter::Summary(reporter));
    }

    fn finish_twins(&mut self, state: &mut Self::State, _topology: &TwinsTopology<P, Self::Case>) {
        state.honest_start = state.reporters.len();
    }

    fn spawn_honest(
        &mut self,
        context: deterministic::Context,
        state: &mut Self::State,
        oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
        participants: &Arc<[PublicKeyOf<P>]>,
        scheme: P::Scheme,
        validator: PublicKeyOf<P>,
        idx: usize,
        topology: &TwinsTopology<P, Self::Case>,
        channels: NetworkChannels<PublicKeyOf<P>>,
    ) {
        let ambiguous: Arc<[u32]> = {
            let mut indices = topology
                .compromised
                .iter()
                .map(|&index| index as u32)
                .collect::<Vec<_>>();
            indices.sort_unstable();
            indices.into()
        };
        let (pending, recovered, resolver) = channels;
        let pending = {
            let (vote_sender, vote_receiver) = pending;
            let sink = sniff_sink(&self.hb_log, idx as u32, participants, &ambiguous);
            let cfg = scheme.certificate_codec_config();
            (
                vote_sender,
                SniffingReceiver::<P, _>::new(vote_receiver, SniffChannel::Vote, cfg, sink),
            )
        };
        let recovered = {
            let (cert_sender, cert_receiver) = recovered;
            let sink = sniff_sink(&self.hb_log, idx as u32, participants, &ambiguous);
            let cfg = scheme.certificate_codec_config();
            (
                cert_sender,
                SniffingReceiver::<P, _>::new(cert_receiver, SniffChannel::Certificate, cfg, sink),
            )
        };
        let resolver = {
            let (backfill_sender, backfill_receiver) = resolver;
            let sink = sniff_sink(&self.hb_log, idx as u32, participants, &ambiguous);
            let cfg = scheme.certificate_codec_config();
            (
                backfill_sender,
                SniffingReceiver::<P, _>::new(backfill_receiver, SniffChannel::Resolver, cfg, sink),
            )
        };
        let spawn = || {
            if self.record_audit {
                TwinsReporter::Recording(spawn_audited_validator::<P, _, _, _, _, _, _, _>(
                    context,
                    oracle,
                    participants.as_ref(),
                    scheme,
                    validator,
                    topology.elector.clone(),
                    state.relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_millis(1_500),
                    self.input.mailbox_size,
                    self.input.fetch_concurrent,
                    self.input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    self.input.certify,
                    self.input.reporting,
                ))
            } else {
                TwinsReporter::Summary(spawn_honest_validator::<P, _, _, _, _, _, _, _>(
                    context,
                    oracle,
                    participants.as_ref(),
                    scheme,
                    validator,
                    topology.elector.clone(),
                    state.relay.clone(),
                    Duration::from_secs(1),
                    Duration::from_millis(1_500),
                    self.input.mailbox_size,
                    self.input.fetch_concurrent,
                    self.input.forwarding,
                    pending,
                    recovered,
                    resolver,
                    self.input.certify,
                    self.input.reporting,
                ))
            }
        };
        let reporter = match &self.hb_log {
            Some(log) => {
                let mut subscriber =
                    happens_before::capture::NodeSubscriber::new(idx as u32, log.clone());
                if let Some(inner) = &self.warn_dispatch {
                    subscriber = subscriber.with_inner(inner.clone());
                }
                let dispatch = Dispatch::new(subscriber);
                dispatcher::with_default(&dispatch, spawn)
            }
            None => spawn(),
        };
        state.reporters.push(reporter);
    }

    async fn observe_liveness(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        prefix_end: View,
    ) {
        if !self.input.configuration.is_valid() {
            context.sleep(MAX_SLEEP_DURATION).await;
            return;
        }
        let mut finalizers = Vec::new();
        for (i, reporter) in state
            .reporters
            .iter_mut()
            .skip(state.honest_start)
            .enumerate()
        {
            let required = self.input.required_containers;
            match self.role {
                TwinsRole::Mutator => {
                    let (mut latest, mut monitor): (View, Receiver<View>) =
                        reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").with_attribute("index", i).spawn(
                        move |_| async move {
                            while latest.get() < required {
                                latest = monitor.recv().await.expect("event missing");
                            }
                        },
                    ));
                }
                TwinsRole::Campaign => {
                    let (_latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.child("finalizer").with_attribute("index", i).spawn(
                        move |_| async move {
                            let mut count = 0u64;
                            while count < required {
                                let view = monitor.recv().await.expect("event missing");
                                if view > prefix_end {
                                    count += 1;
                                }
                            }
                        },
                    ));
                }
            }
        }
        join_all(finalizers).await;
    }

    fn check_invariants(
        &mut self,
        context: &deterministic::Context,
        state: &mut Self::State,
        topology: &TwinsTopology<P, Self::Case>,
    ) {
        let config = self.input.configuration;
        if !config.is_valid() {
            return;
        }
        if let Some(log) = &self.hb_log {
            let summary = log.summary();
            let mut tokens = summary.tokens();
            if let Some(bucket) = summary.dispersion_bucket() {
                tokens.insert(format!("hb:dispersion={bucket}"));
            }
            tokens.extend(summary.lsh_tokens());
            state_cov::observe_tokens(tokens);
        }
        let honest_reporters = &state.reporters[state.honest_start..];
        let honest_summaries = honest_reporters
            .iter()
            .map(TwinsReporter::summary)
            .collect::<Vec<_>>();
        let observers = state
            .twin_observers
            .iter()
            .chain(state.reporters.iter())
            .map(TwinsReporter::summary)
            .collect::<Vec<_>>();
        invariants::check_vote_invariants_with_byzantine(
            &topology.compromised,
            topology.elector.clone(),
            Epoch::new(EPOCH),
            topology.term_length,
            &observers,
        );
        if self.state_coverage {
            let reporter_states =
                state_cov::encode_reporter_states(&honest_summaries, config.n as usize);
            state_cov::observe_with_metrics(&reporter_states, &context.encode());
        }
        if self.record_audit {
            let recordings = honest_reporters
                .iter()
                .filter_map(TwinsReporter::recording)
                .collect::<Vec<_>>();
            assert_eq!(
                recordings.len(),
                honest_reporters.len(),
                "every correct Twins reporter must record in audit mode"
            );
            invariants::check::<P>(topology.term_length, recordings.as_slice());
        } else {
            invariants::check::<P>(topology.term_length, invariants::extract(honest_summaries));
        }
    }
}

/// Unified twins driver. The two existing modes (TwinsMutator / TwinsCampaign)
/// share scenario sampling, forwarders/routers, twin-half splitting, the
/// primary engine, the honest validators, and the byzantine-aware invariants.
/// Only the secondary half (Disrupter vs full engine) and the liveness wait
/// shape (absolute view vs prefix-trailing count) differ; both are keyed on
/// `role`. Liveness and state extraction run over honest reporters only;
/// signer-filtered vote/fault checks also observe twin reporters (Campaign
/// halves and the retained Mutator primary).
///
/// Happens-before capture covers honest validators only: twin halves share
/// one identity across two engines, so neither tracing attribution nor
/// sender-resolved merges are sound for them; honest receives from a twin
/// resolve to no sender. When `record_audit` is true, only correct engines use
/// the append-only reporter and automaton wrappers. Returns the summary when
/// capture is enabled.
fn run_twins<P: simplex::Simplex>(
    mut input: FuzzInput,
    role: TwinsRole,
    state_coverage: bool,
    happens_before: bool,
    record_audit: bool,
) -> Option<happens_before::Summary> {
    if state_coverage || happens_before {
        state_cov::reset();
    }
    input.partition = Partition::Connected;
    input.configuration = N4F1C3;
    // Twins reuse the standard input; a certify variant sampled for an
    // all-honest configuration would stall this quorum-tight one.
    input.certify = CertifyChoice::Always;

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let hb_log = happens_before.then(happens_before::capture::EventLog::new);

    let hb_log_run = hb_log.clone();
    let execute = |warn_dispatch: Option<Dispatch>| {
        executor.start(|mut context| async move {
            let mut backend = MockTwinsBackend::<P>::new(
                input,
                role,
                state_coverage,
                record_audit,
                hb_log_run,
                warn_dispatch,
            );
            run_twins_with_backend::<P, _>(&mut context, &mut backend).await;
        });
    };

    if happens_before {
        if state_coverage {
            // Per-node subscribers shadow the collector for validator tasks, so
            // its dispatch is teed through them to keep trace-event tokens fed.
            run_with_warn_trace_collection(|dispatch| execute(Some(dispatch.clone())));
        } else {
            execute(None);
        }
    } else if state_coverage {
        run_with_warn_trace_collection(|_| execute(None));
    } else {
        execute(None);
    }

    // Tokens are observed inside `execute` (before the invariant checks) so a
    // bug-finding panic still credits its interleaving. Here we only surface the
    // summary for the return value.
    hb_log.as_ref().map(|log| log.summary())
}

fn run_fuzz_node<P: simplex::Simplex, M: simplex_node::NodeFuzzMode>(input: NodeFuzzInput)
where
    PublicKeyOf<P>: Send,
{
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);
    let mailbox_size = input.mailbox_size;
    let fetch_concurrent = input.fetch_concurrent;
    let forwarding = input.forwarding;
    let certify = input.certify;
    let reporting = input.reporting;
    let term_length = P::effective_term_length(input.term_length);

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
            simplex_node::run_recovery::<P>(
                checkpoint,
                participants,
                schemes,
                term_length,
                mailbox_size,
                fetch_concurrent,
                forwarding,
                certify,
                reporting,
            );
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
    MalloryContainer,
}

pub trait FuzzMode {
    const MODE: Mode;
}

/// Whether a harness run also emits protocol-state coverage feedback.
///
/// Orthogonal to [`FuzzMode`]: any honest-reporter mode (Standard, FaultyNet,
/// TwinsMutator, TwinsCampaign) can run with or without the [`state_cov`] signal.
pub trait Coverage {
    /// When `true`, the run projects its honest reporters through
    /// [`state_cov::observe_with_metrics`] so libFuzzer also tracks protocol-state novelty.
    const STATE: bool;
    /// When `true`, per-node subscribers capture a happens-before summary of the run
    /// (see [`happens_before`]) and fold its causal-pair tokens into the same table.
    const HAPPENS_BEFORE: bool = false;
}

/// Only libFuzzer's default code-edge coverage; no protocol-state feedback (the
/// baseline).
pub struct CodeCoverage;
impl Coverage for CodeCoverage {
    const STATE: bool = false;
}

/// Protocol-state coverage feedback enabled (see [`state_cov`]).
pub struct StateCoverage;
impl Coverage for StateCoverage {
    const STATE: bool = true;
}

/// Happens-before coverage only: per-node causal-interleaving novelty without the
/// protocol-state signal (see [`happens_before`]). The baseline HB target.
pub struct HappensBeforeCoverage;
impl Coverage for HappensBeforeCoverage {
    const STATE: bool = false;
    const HAPPENS_BEFORE: bool = true;
}

/// Happens-before coverage layered on top of the protocol-state signal: both feed
/// the same table so their contributions combine (see [`happens_before`] and
/// [`state_cov`]).
pub struct HappensBeforeStateCoverage;
impl Coverage for HappensBeforeStateCoverage {
    const STATE: bool = true;
    const HAPPENS_BEFORE: bool = true;
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

/// **Mallory** - the dedicated adaptive-adversary runner over its own fault catalog,
/// bounded by a whole-episode CONTAINER (distinct-finalization) budget.
///
/// Each episode selects one adversary environment for the faultable identity
/// (node 0): honest, or one of six Byzantine profiles (Disrupter, Conflicter,
/// Nuller, Equivocator, Impersonator, Outdated). It then drives a reactive loop of
/// observe-orient-decide-act steps. Each step observes the honest happens-before
/// fingerprint (the Q-state) and protocol-state descriptor, then selects a fault
/// from the stable catalog (`mallory::fault`) under a legal mask. The fault is a
/// network (isolation, partition), packet (delay/loss/corrupt/duplicate/reorder), or
/// lifecycle (crash-stop, durable restart, amnesia restart) fault. It applies the
/// fault, then reacts: the step ends on the first new honest finalization past its
/// baseline, or a deterministic per-action timeout if the fault suppressed progress.
/// The fault heals and (for the learned chooser) a temporal-difference update rewards
/// novel state and happens-before fingerprints (the pre-heal fault effect) via the
/// backend-agnostic Q-core in `mallory::policy`. The whole episode stops once it has
/// observed the input's `required_containers` distinct finalization boundaries (each
/// step counts at most one; view jumps and duplicate reports count once), or when it
/// hits the `max(MALLORY_EPISODE_STEPS, required_containers)` truncation cap. A
/// crash-stop is permanent but does NOT end the episode: the loop continues over the
/// surviving quorum. Mallory does not reuse the ByzzFuzz fault machinery: it builds
/// its own setup from the shared harness helpers and never samples ByzzFuzz
/// `(c, d, r)`.
///
/// The episode-end oracle checks liveness (each live correct node must finalize past
/// its pre-heal frontier) and the vote / state-extraction safety invariants. It runs
/// over the episode's honest reporter set, excluding an unmanaged Byzantine node 0, a
/// crash-stopped node from liveness, and an amnesiac node from the honest set. The
/// name is kept as `MalloryContainer` to avoid target / API churn. See
/// `mallory::runner::run`.
pub struct MalloryContainer;
impl FuzzMode for MalloryContainer {
    const MODE: Mode = Mode::MalloryContainer;
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

/// Install (once per process) a panic-hook chain that drains and prints the
/// Mallory decision log when `CONSENSUS_FUZZ_LOG` is set (any value). Mirrors
/// [`install_byzzfuzz_panic_hook`] over the separate Mallory log; the same
/// ordering (log -> default message -> libfuzzer trace) applies.
fn install_mallory_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let dump = std::env::var_os(FUZZ_LOG_ENV).is_some();
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if dump {
                let log = mallory::log::take();
                if !log.is_empty() {
                    eprintln!("---- Mallory decision log ({} entries) ----", log.len());
                    for line in &log {
                        eprintln!("{line}");
                    }
                    eprintln!("---- end of Mallory decision log ----");
                }
            }
            prev(info);
        }));
    });
}

pub fn fuzz<P: simplex::Simplex, M: FuzzMode, C: Coverage>(mut input: FuzzInput) {
    if matches!(M::MODE, Mode::Byzzfuzz) {
        install_byzzfuzz_panic_hook();
    } else if matches!(M::MODE, Mode::MalloryContainer) {
        install_mallory_panic_hook();
    } else {
        if matches!(M::MODE, Mode::FaultyNet) {
            // We run only fuzzing with network faults, populated later by the
            // chosen strategy.
            input.partition = Partition::Adaptive(Vec::new());
        }
        print_fuzz_input::<P>(M::MODE, &input);
    }

    let raw_bytes = input.raw_bytes.clone();
    let run_result = match M::MODE {
        Mode::Standard => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::FaultyMessaging => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_faulty_messaging::<P>(input)
        })),
        Mode::FaultyNet => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::TwinsMutator => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twins_mutator::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::TwinsCampaign => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            run_with_twins_campaign::<P>(input, C::STATE, C::HAPPENS_BEFORE)
        })),
        Mode::Byzzfuzz => {
            panic::catch_unwind(panic::AssertUnwindSafe(|| byzzfuzz::run::<P>(input)))
        }
        Mode::MalloryContainer => panic::catch_unwind(panic::AssertUnwindSafe(|| {
            mallory::runner::run::<P>(input, mallory::runner::Chooser::Learned)
        })),
    };
    match run_result {
        Ok(()) => {
            // Drain the byzzfuzz log on success too so a *next* run (Byzzfuzz
            // or otherwise) starts clean. This is cheap when the log is empty.
            if matches!(M::MODE, Mode::Byzzfuzz) {
                let _ = byzzfuzz::log::take();
            }
            // Same for the separate Mallory log.
            if matches!(M::MODE, Mode::MalloryContainer) {
                let _ = mallory::log::take();
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

/// Fuzz the Standard Simplex harness with the append-only recording reporter
/// and recording automaton.
///
/// Unlike [`fuzz`], this is an explicit opt-in used only by dedicated audit
/// targets. It runs the same basic and vote invariants as Standard mode, then
/// dispatches the additional audit invariants through [`invariants::check`].
pub fn fuzz_audit<P: simplex::Simplex>(mut input: FuzzInput) {
    // Rejected certification is sampled only for instantiations that expose a
    // statically known Byzantine-led view. General fuzz targets never receive
    // this override, so they cannot accidentally reject a correct proposer's
    // certifiable-by-construction payload. The known Byzantine-led view assumes
    // the rotating (term length one) leader schedule, so longer terms skip it.
    if input.certify == CertifyChoice::Always
        && input.term_length == TermLength::ONE
        && input.raw_bytes.first().is_some_and(|byte| byte % 4 == 0)
        && let Some(view) = P::audit_rejection_view(input.configuration)
        && input.required_containers >= view.get()
    {
        input.certify = CertifyChoice::RejectView { view };
    }
    print_fuzz_input::<P>(Mode::Standard, &input);

    let raw_bytes = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        run_audited_standard_once::<P>(input)
    }));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes);
        panic::resume_unwind(payload);
    }
}

/// Fuzz a Twins harness while recording append-only activity and automaton
/// history for correct engines. Compromised twin halves retain the ordinary
/// summary Reporter and participate only in signer-filtered vote checks.
pub fn fuzz_twins_audit<P: simplex::Simplex, M: FuzzMode>(input: FuzzInput) {
    let role = match M::MODE {
        Mode::TwinsMutator => TwinsRole::Mutator,
        Mode::TwinsCampaign => TwinsRole::Campaign,
        mode => panic!("fuzz_twins_audit requires a Twins mode, got {mode:?}"),
    };
    print_fuzz_input::<P>(M::MODE, &input);

    let raw_bytes = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let _ = run_twins::<P>(input, role, false, false, true);
    }));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes);
        panic::resume_unwind(payload);
    }
}

pub fn fuzz_node<P: simplex::Simplex, M: simplex_node::NodeFuzzMode>(input: NodeFuzzInput) {
    print_node_fuzz_input::<P>(M::MODE, &input);

    let raw_bytes_for_panic = input.raw_bytes.clone();
    let run_result = panic::catch_unwind(panic::AssertUnwindSafe(|| run_fuzz_node::<P, M>(input)));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes_for_panic);
        panic::resume_unwind(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_input() -> FuzzInput {
        FuzzInput {
            raw_bytes: 0u64.to_be_bytes().to_vec(),
            required_containers: MIN_REQUIRED_CONTAINERS,
            term_length: TermLength::ONE,
            degraded_network: false,
            configuration: N4F0C4,
            partition: Partition::Connected,
            strategy: StrategyChoice::AnyScope,
            messaging_faults: Vec::new(),
            mailbox_size: DEFAULT_MAILBOX_SIZE,
            fetch_concurrent: DEFAULT_FETCH_CONCURRENT,
            forwarding: ForwardingPolicy::Disabled,
            certify: CertifyChoice::Always,
            reporting: ReporterWiring::Solo,
        }
    }

    #[test]
    fn warn_trace_collection_does_not_perturb_standard_run() {
        let input = audit_input();

        let unwrapped =
            run_standard_once::<simplex::SimplexId>(input.clone(), false, true, false, None)
                .expect("valid connected run should produce audit data");
        let wrapped = run_with_warn_trace_collection(|_| {
            run_standard_once::<simplex::SimplexId>(input, false, true, false, None)
        })
        .expect("valid connected run should produce audit data");

        assert_eq!(unwrapped.auditor_state, wrapped.auditor_state);
        assert_eq!(unwrapped.reporter_states, wrapped.reporter_states);
    }

    #[cfg(feature = "mocks")]
    #[test]
    fn audited_standard_checks_simplex_id_and_certificate_mock() {
        assert!(run_audited_standard_once::<simplex::SimplexId>(audit_input()).0);
        assert!(run_audited_standard_once::<simplex::SimplexCertificateMock>(audit_input()).0);
    }

    #[test]
    fn audited_twins_checks_campaign_and_mutator() {
        for role in [TwinsRole::Campaign, TwinsRole::Mutator] {
            let _ = run_twins::<simplex::SimplexId>(audit_input(), role, false, false, true);
        }
    }

    #[test]
    fn audited_standard_observes_rejected_certification() {
        let mut input = audit_input();
        input.configuration = N4F1C3;
        input.required_containers = 4;
        // With epoch 333 and four round-robin participants, view 3 is led by
        // the compromised participant at index 0. Rejecting that proposal does
        // not violate any correct proposer's certifiable-by-construction duty.
        input.certify = CertifyChoice::RejectView { view: View::new(3) };
        let (valid, rejected) = run_audited_standard_once::<simplex::SimplexId>(input);
        assert!(valid, "audit run was not checked");
        assert!(rejected, "audit run did not reach false certification");
    }

    #[test]
    fn certify_variants_preserve_liveness_with_full_honesty() {
        // With four honest validators, disabling one certifier leaves exactly
        // the finalize quorum. Both incomplete-result paths must retain
        // liveness.
        for certify in [
            CertifyChoice::SingleCancel { target_idx: 0 },
            CertifyChoice::SinglePending { target_idx: 0 },
        ] {
            let mut input = audit_input();
            input.certify = certify;
            let audit = run_standard_once::<simplex::SimplexId>(input, false, true, false, None);
            assert!(audit.is_some(), "run with {certify:?} produced no audit");
        }
    }

    #[test]
    fn rejected_byzantine_leader_view_preserves_liveness() {
        let mut input = audit_input();
        input.configuration = N4F1C3;
        input.required_containers = 4;
        input.certify = CertifyChoice::RejectView { view: View::new(3) };
        let (valid, rejected) = run_audited_standard_once::<simplex::SimplexId>(input);
        assert!(valid, "rejecting one Byzantine-led view prevented recovery");
        assert!(rejected, "the Byzantine-led view was not rejected");
    }

    #[test]
    fn twins_happens_before_traces_honest_validators_only() {
        // N4F1C3 twins compromise one identity (two engines, one key): the
        // three honest validators are captured, twin halves contribute no
        // attributed events, and receives from the twin merge nothing.
        let summary =
            run_twins::<simplex::SimplexId>(audit_input(), TwinsRole::Campaign, false, true, false)
                .expect("happens-before summary");
        assert_eq!(summary.node_count(), 3, "only honest validators tracked");
        assert!(!summary.tokens().is_empty());
    }

    #[test]
    fn resolver_sniff_decodes_backfill_responses() {
        use commonware_codec::Encode;
        use commonware_consensus::{
            simplex::types::{Notarization, Notarize, Proposal},
            types::Round,
        };

        let executor = deterministic::Runner::seeded(7);
        executor.start(|mut context| async move {
            let (_, schemes) =
                <simplex::SimplexId as simplex::Simplex>::setup(&mut context, NAMESPACE, 4);
            let proposal = Proposal::new(
                Round::new(Epoch::new(EPOCH), View::new(3)),
                View::new(2),
                Sha256Digest::from([7u8; 32]),
            );
            let votes: Vec<_> = schemes[..3]
                .iter()
                .map(|s| Notarize::sign(s, proposal.clone()).unwrap())
                .collect();
            let cert = Certificate::Notarization(
                Notarization::from_notarizes(&schemes[0], &votes, &Sequential).unwrap(),
            );
            let cfg = schemes[0].certificate_codec_config();

            let response = ResolverMessage::<U64> {
                id: 9,
                payload: ResolverPayload::Response(cert.encode()),
            };
            assert_eq!(
                sniff_event::<simplex::SimplexId>(
                    SniffChannel::Resolver,
                    &IoBuf::from(response.encode()),
                    &cfg,
                ),
                Some((3, happens_before::EventKind::ReceiveNotarization)),
            );

            // Requests deliver no certificate; nothing is recorded.
            let request = ResolverMessage::<U64> {
                id: 9,
                payload: ResolverPayload::Request(U64::from(3u64)),
            };
            assert_eq!(
                sniff_event::<simplex::SimplexId>(
                    SniffChannel::Resolver,
                    &IoBuf::from(request.encode()),
                    &cfg,
                ),
                None,
            );
        });
    }

    #[test]
    fn happens_before_capture_is_node_attributed_and_deterministic() {
        let input = audit_input();

        let a = run_standard_once::<simplex::SimplexId>(input.clone(), false, true, true, None)
            .expect("valid connected run should produce audit data");
        let b = run_standard_once::<simplex::SimplexId>(input, false, true, true, None)
            .expect("valid connected run should produce audit data");

        let summary = a.happens_before.as_ref().expect("hb capture requested");
        // Dispatch propagation attributed events to each honest validator, and each
        // recorded real causal history over a live run.
        assert!(
            summary.node_count() >= 2,
            "expected multiple attributed nodes, got {}",
            summary.node_count()
        );
        assert!(
            !summary.tokens().is_empty(),
            "expected non-empty happens-before token set"
        );
        // p2p-boundary sniffing captured wire arrivals of votes (which tracing
        // cannot observe): notarize votes are exchanged on the way to finalization.
        assert!(
            summary.tokens().iter().any(|t| t.contains("recv_notarize")),
            "expected p2p-sniffed vote-arrival tokens"
        );
        // Certificate arrival (p2p) and certificate processing (tracing) are
        // captured as distinct events.
        let toks = summary.tokens();
        assert!(
            toks.iter().any(|t| t.contains("recv_notarization")),
            "expected p2p-sniffed certificate-arrival tokens"
        );
        assert!(
            toks.iter().any(|t| t.contains("proc_")),
            "expected tracing certificate-processing tokens"
        );
        // Same seed and inputs must yield an identical summary.
        assert_eq!(a.happens_before, b.happens_before);
    }

    #[test]
    fn happens_before_tee_preserves_warn_trace_collection() {
        let input = audit_input();
        let collect = |happens_before: bool| {
            let store = TraceStorage::default();
            let dispatch = warn_trace_dispatch(store.clone());
            let warn_dispatch = happens_before.then(|| dispatch.clone());
            let audit = dispatcher::with_default(&dispatch, || {
                run_standard_once::<simplex::SimplexId>(
                    input.clone(),
                    false,
                    true,
                    happens_before,
                    warn_dispatch,
                )
            })
            .expect("valid connected run should produce audit data");
            let events: Vec<_> = store.get_all().iter().map(|e| format!("{e:?}")).collect();
            (audit, events)
        };

        let (_, plain) = collect(false);
        let (audit, teed) = collect(true);
        // Both signals coexist: the per-node subscribers captured happens-before
        // events while the shadowed collector still received the identical
        // trace-event stream (spans included) through the tee.
        assert!(audit.happens_before.is_some());
        assert!(!plain.is_empty(), "expected collected trace events");
        assert_eq!(plain, teed);
    }
}

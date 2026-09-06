pub mod block_relay;
pub mod bounds;
pub mod disrupter;
pub mod network;
pub mod simplex;
pub mod simplex_audit;
#[cfg(any(feature = "mocks", test))]
pub use commonware_consensus::simplex::mocks::scheme as simplex_certificate_mock;
pub mod strategy;
mod twins_network;
pub use twins_network::resolver_view as twins_resolver_view;
pub mod types;
pub mod utils;
use crate::{
    disrupter::Disrupter,
    simplex_audit::{RecordingAutomaton, RecordingReporter},
    strategy::{
        AnyScope, FutureScope, HeaderScope, SmallScope, SplitHeader, Strategy, StrategyChoice,
    },
    utils::{Action, Partition, SetPartition, apply_partition, link_peers, register},
};
use arbitrary::Arbitrary;
use commonware_actor::Feedback;
use commonware_consensus::{
    CertifiableAutomaton, Monitor, Relay as ConsensusRelay, Reporter, Reporters,
    simplex::{
        Engine, Floor, ForwardPolicy, Plan, SkipBudget, SkipPolicy, config,
        elector::Config as ElectorConfig,
        mocks::{application, relay, reporter, twins},
        types::{Activity, Context as SimplexContext},
    },
    types::{Delta, Epoch, TermLength, View, ViewDelta},
};
use commonware_cryptography::{
    PublicKey as CryptoPublicKey, Sha256, certificate::Verifier, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Handle, Spawner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{
    FuzzRng, NZU16, NZU32, NZUsize,
    channel::mpsc::{self, Receiver},
    probability,
};
#[cfg(any(feature = "mocks", test))]
pub use simplex::{
    SimplexCertificateMock, SimplexCertificateMockByzantineFirstLeader,
    SimplexCertificateMockCustomRoundRobin,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    num::{NonZeroU16, NonZeroUsize},
    panic,
    sync::Arc,
    time::Duration,
};
pub const EPOCH: u64 = 333;

pub const FUZZ_LOG_ENV: &str = "CONSENSUS_FUZZ_LOG";

pub const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
/// Index of the byzantine validator in `participants`. Single source of truth
/// for the fixed byzantine identity used by the ByzzFuzz and marshal multi-node
/// models (sender selection, injector key, invariant/liveness exclusion).
pub const BYZANTINE_IDX: usize = 0;
pub const FAULT_INJECTION_RATIO: u64 = 5;
pub const MIN_NUMBER_OF_FAULTS: u64 = 2;
pub const MIN_REQUIRED_CONTAINERS: u64 = 1;
pub const MAX_REQUIRED_CONTAINERS: u64 = 30;
pub const MAX_TERM_LENGTH: u32 = 5;
/// Scripted adversarial rounds a twins campaign generates at most. Each round
/// is one leader term, so the scripted prefix spans `rounds * term_length`
/// views before the liveness gate starts counting.
pub const TWINS_MAX_ROUNDS: u64 = 8;
pub const MAX_SLEEP_DURATION: Duration = Duration::from_secs(15);
pub const FUZZ_RUNTIME_TIMEOUT_FLOOR: Duration = Duration::from_secs(360);
/// Budget per finalization a liveness gate demands. Sized for stable leaders
/// facing an equivocating twin, where a nullify inside a term withholds
/// finalize votes for the rest of that term (see `Same-Term Vote Safety` in
/// [commonware_consensus::simplex]), so a finalization costs several views.
const FUZZ_RUNTIME_TIMEOUT_PER_CONTAINER: Duration = Duration::from_secs(14);
/// Budget per view of a twins run's scripted adversarial prefix, sized for a
/// term that stalls rather than one that certifies promptly.
const FUZZ_RUNTIME_TIMEOUT_PER_PREFIX_VIEW: Duration = Duration::from_secs(3);
/// Bounded pre-GST fault phase: how long network faults stay active before a
/// run that has not already finished is given a GST transition. Shared by the
/// ByzzFuzz runner and the marshal multi-node liveness runner.
pub const FAULT_PHASE: Duration = Duration::from_secs(30);
pub const NAMESPACE: &[u8] = b"consensus_fuzz";
pub const MAX_RAW_BYTES: usize = 32_768;
pub const DEFAULT_MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);

/// Simulated-time deadline for a run, derived from the work it demands: a run
/// traverses `prefix_views` scripted adversarial views (zero outside twins) and
/// then waits for `required_containers` finalizations at every checked reporter.
/// The floor keeps cheap runs at the budget they have always had.
pub fn fuzz_runtime_timeout(required_containers: u64, prefix_views: u64) -> Duration {
    let scale =
        |unit: Duration, count: u64| unit.saturating_mul(u32::try_from(count).unwrap_or(u32::MAX));
    scale(FUZZ_RUNTIME_TIMEOUT_PER_CONTAINER, required_containers)
        .saturating_add(scale(FUZZ_RUNTIME_TIMEOUT_PER_PREFIX_VIEW, prefix_views))
        .max(FUZZ_RUNTIME_TIMEOUT_FLOOR)
}

/// Views of scripted adversarial prefix a twins run traverses before its
/// liveness gate opens (see `MockTwinsBackend::framework`).
pub fn twins_prefix_views(required_containers: u64, term_length: TermLength) -> u64 {
    required_containers
        .clamp(1, TWINS_MAX_ROUNDS)
        .saturating_mul(term_length.get())
}

pub fn bounded_fuzz_runtime_config(
    raw_bytes: &[u8],
    required_containers: u64,
    prefix_views: u64,
) -> deterministic::Config {
    deterministic::Config::new()
        .with_rng(FuzzRng::new(raw_bytes.to_vec()))
        .with_timeout(Some(fuzz_runtime_timeout(
            required_containers,
            prefix_views,
        )))
}

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

    /// Returns true when every quorum intersection contains an honest
    /// participant, so certificate-derived safety invariants are meaningful.
    pub fn can_finalize(&self) -> bool {
        self.faults <= bounds::max_faults(self.n)
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
        success_rate: probability!(0.6),
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

/// Per-iteration filter for fuzz-local mock block payload delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockFilterChoice {
    None,
    DropRecipient { view: View, target_idx: u8 },
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
            .field("mailbox_size", &input.mailbox_size)
            .field("forwarding", &input.forwarding)
            .field("certify", &input.certify)
            .field("block_filter", &input.block_filter)
            .field("reporting", &input.reporting)
            .finish()
    }
}

pub fn print_fuzz_input<P: simplex::Simplex>(mode: Mode, input: &FuzzInput) {
    if std::env::var_os(FUZZ_LOG_ENV).is_some() {
        eprintln!(
            "consensus fuzz configuration: mode={mode:?} effective_term_length={:?} input={:?}",
            P::effective_term_length(input.term_length),
            FuzzInputDebug(input)
        );
    }
}

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub required_containers: u64,
    pub term_length: TermLength,
    /// Sampled but not yet handed to engines (see `PINNED_OPTIMISTIC_VIEWS`).
    pub optimistic_views: ViewDelta,
    /// Sampled but not yet handed to engines (see `PINNED_OPTIMISTIC_VIEWS`).
    pub heterogeneous_optimism: bool,
    pub degraded_network: bool,
    pub configuration: Configuration,
    pub partition: Partition,
    pub strategy: StrategyChoice,
    /// Per-iteration mailbox capacity threaded into every honest engine.
    pub mailbox_size: NonZeroUsize,
    /// Per-iteration forwarding policy threaded into every engine the harness
    /// spawns. Sampling lets the fuzzer drive coverage of all three arms of
    /// `batcher::forward_targets` instead of pinning to `Disabled`.
    pub forwarding: ForwardPolicy,
    /// Per-iteration certify policy threaded into every honest validator
    /// the harness spawns.
    pub certify: CertifyChoice,
    /// Per-iteration fuzz-local mock block relay filter.
    pub block_filter: BlockFilterChoice,
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
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));
        let optimistic_views =
            ViewDelta::new(u.int_in_range(0..=max_optimistic_views(term_length))?);
        let heterogeneous_optimism = u.arbitrary()?;

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
            0 => ForwardPolicy::Disabled,
            1 => ForwardPolicy::SilentVoters,
            _ => ForwardPolicy::SilentLeader,
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

        let block_filter = if configuration == N4F1C3 && u.int_in_range(0..=9)? == 0 {
            BlockFilterChoice::DropRecipient {
                view: View::new(u.int_in_range(1..=fault_rounds_bound)?),
                target_idx: u
                    .int_in_range(configuration.faults as u8..=configuration.n as u8 - 1)?,
            }
        } else {
            BlockFilterChoice::None
        };

        let reporting = ReporterWiring::arbitrary(u)?;

        let mailbox_size = fuzz_mailbox_size(u)?;

        // Collect bytes for RNG
        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = u.bytes(remaining)?.to_vec();

        Ok(Self {
            raw_bytes,
            partition,
            configuration,
            degraded_network,
            required_containers,
            term_length,
            optimistic_views,
            heterogeneous_optimism,
            strategy,
            mailbox_size,
            forwarding,
            certify,
            block_filter,
            reporting,
        })
    }
}

pub type PublicKeyOf<P> = <<P as simplex::Simplex>::Scheme as Verifier>::PublicKey;
pub type CertCfgOf<P> =
    <<<P as simplex::Simplex>::Scheme as Verifier>::Certificate as commonware_codec::Read>::Cfg;

/// Largest fuzzed optimistic-view value: the domain `[0, term_length + 2]`
/// covers 0 (optimistic validation disabled), the term-length boundary, and
/// values beyond the term length, which production accepts but caps.
fn max_optimistic_views(term_length: TermLength) -> u64 {
    term_length.get() + 2
}

/// Optimistic lookahead wired into engines and reference electors.
///
/// Pinned to zero: the entry-evidence invariants (contiguous certificate
/// progression, certified notarization parents, per-vote entry evidence)
/// assume non-optimistic view entry, and a run truncated inside an optimistic
/// issuance window would trip them without a real violation. The fuzzed
/// [`FuzzInput::optimistic_views`] and [`FuzzInput::heterogeneous_optimism`]
/// dimensions stay in the input format but are not handed to engines until
/// those invariants understand optimism.
pub const PINNED_OPTIMISTIC_VIEWS: ViewDelta = ViewDelta::zero();

pub type NetworkChannels<P> = (
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
pub async fn setup_network<P: simplex::Simplex>(
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
            max_peers_per_set: NZUsize!(participants.len()),
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
        success_rate: probability!(1.0),
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

/// Start a Disrupter with an explicit consensus `epoch`.
/// The marshal liveness target passes `Epoch::zero()` so the disrupter shares
/// the epoch its honest engines run in (making it an in-epoch adversary rather
/// than wrong-epoch noise).
// Only the mocks-gated marshal end-to-end runner calls this thin wrapper; the
// other disrupter paths use the `_and_relay`/`_relay_and_tag` variants directly.
#[cfg(feature = "mocks")]
#[allow(clippy::too_many_arguments)]
pub fn start_disrupter_with_epoch<P: simplex::Simplex>(
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
    start_disrupter_with_epoch_and_relay::<P>(
        context,
        scheme,
        strategy,
        required_containers,
        epoch,
        vote_network,
        certificate_network,
        resolver_network,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn start_disrupter_with_epoch_and_relay<P: simplex::Simplex>(
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
    block_relay: Option<Arc<block_relay::Relay<PublicKeyOf<P>>>>,
) {
    start_disrupter_with_epoch_relay_and_tag::<P>(
        context,
        scheme,
        strategy,
        required_containers,
        epoch,
        vote_network,
        certificate_network,
        resolver_network,
        block_relay,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_disrupter_with_epoch_relay_and_tag<P: simplex::Simplex>(
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
    block_relay: Option<Arc<block_relay::Relay<PublicKeyOf<P>>>>,
    block_relay_tag: Option<u64>,
) {
    match *strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new_with_epoch_relay_and_tag(
                context,
                scheme,
                SmallScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
                epoch,
                block_relay,
                block_relay_tag,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::AnyScope => {
            let disrupter = Disrupter::new_with_epoch_relay_and_tag(
                context,
                scheme,
                AnyScope,
                required_containers,
                epoch,
                block_relay,
                block_relay_tag,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new_with_epoch_relay_and_tag(
                context,
                scheme,
                FutureScope {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
                epoch,
                block_relay,
                block_relay_tag,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::HeaderScope {
            fault_rounds,
            fault_rounds_bound,
            mutation,
        } => {
            let disrupter = Disrupter::new_with_epoch_relay_and_tag(
                context,
                scheme,
                HeaderScope {
                    fault_rounds,
                    fault_rounds_bound,
                    mutation,
                },
                required_containers,
                epoch,
                block_relay,
                block_relay_tag,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
        StrategyChoice::SplitHeader {
            fault_rounds,
            fault_rounds_bound,
        } => {
            let disrupter = Disrupter::new_with_epoch_relay_and_tag(
                context,
                scheme,
                SplitHeader {
                    fault_rounds,
                    fault_rounds_bound,
                },
                required_containers,
                epoch,
                block_relay,
                block_relay_tag,
            );
            disrupter.start(vote_network, certificate_network, resolver_network);
        }
    }
}

/// Whether a [`ManagedValidator`]'s engine is running, has been crash-stopped, or
/// was restarted with empty storage.
/// A crash-stop is permanent for the crashed INCARNATION but not terminal for the
/// run: after [`Running`](Self::Running) transitions to [`Crashed`](Self::Crashed)
/// the old engine/application tasks are aborted and never resurrected, yet the
/// episode continues over the surviving quorum (the crashed node is dropped from the
/// liveness watch; its retained reporter stays in the safety set). A durable restart
/// is a separate fault that rebuilds fresh tasks and returns to `Running` in one
/// step, so it never leaves the node in `Crashed` (see `commonware_consensus_fuzz_simplex::mallory::lifecycle`).
/// An [`Amnesiac`](Self::Amnesiac) node has a LIVE engine but was rebuilt on a fresh
/// (empty) storage partition, so it has forgotten its durable state (including signed
/// votes) and may equivocate: it is treated as Byzantine for the rest of the episode
/// (excluded from the honest safety and liveness sets), not terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValidatorLifecycle {
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
pub struct ManagedValidator<
    P,
    R = reporter::Reporter<
        deterministic::Context,
        <P as simplex::Simplex>::Scheme,
        <P as simplex::Simplex>::Elector,
        Sha256Digest,
    >,
> where
    P: simplex::Simplex,
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
    reporter: R,
    /// Application actor handle, retained so a crash can abort it. `None` once
    /// taken by a crash/restart.
    app_handle: Option<Handle<()>>,
    /// Engine handle, retained so a crash can abort it (aborting cascades to every
    /// engine sub-task). `None` once taken by a crash/restart.
    engine_handle: Option<Handle<()>>,
    /// Whether the engine is currently running or has been crash-stopped.
    lifecycle: ValidatorLifecycle,
}

impl<P, R> ManagedValidator<P, R>
where
    P: simplex::Simplex,
    R: Clone,
{
    /// A clone of the Arc-backed reporter (shares live state with this validator).
    pub fn reporter(&self) -> R {
        self.reporter.clone()
    }

    /// This validator's index in the participant set.
    pub fn idx(&self) -> usize {
        self.idx
    }

    /// This validator's public key.
    pub fn validator(&self) -> &PublicKeyOf<P> {
        &self.validator
    }

    /// This validator's signing scheme.
    pub fn scheme(&self) -> &P::Scheme {
        &self.scheme
    }

    /// The durable storage partition (stable across incarnations).
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// The current lifecycle state.
    pub fn lifecycle(&self) -> ValidatorLifecycle {
        self.lifecycle
    }

    /// Take the engine handle for a crash/restart abort, leaving `None`.
    pub fn take_engine_handle(&mut self) -> Option<Handle<()>> {
        self.engine_handle.take()
    }

    /// Take the application handle for a crash/restart abort, leaving `None`.
    pub fn take_app_handle(&mut self) -> Option<Handle<()>> {
        self.app_handle.take()
    }

    /// Mark the engine crash-stopped after both handles were aborted and awaited.
    pub fn mark_crashed(&mut self) {
        self.lifecycle = ValidatorLifecycle::Crashed;
    }

    /// Adopt a freshly rebuilt incarnation: take over its engine/application
    /// handles, bump the generation, and return to `Running`. The reporter is
    /// unchanged (a durable restart reuses the same instance).
    pub fn adopt(&mut self, rebuilt: ManagedValidator<P, R>) {
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
    pub fn adopt_amnesiac(&mut self, rebuilt: ManagedValidator<P, R>) {
        self.app_handle = rebuilt.app_handle;
        self.engine_handle = rebuilt.engine_handle;
        self.partition = rebuilt.partition;
        self.reporter = rebuilt.reporter;
        self.generation = self.generation.wrapping_add(1);
        self.lifecycle = ValidatorLifecycle::Amnesiac;
    }

    /// This validator's current incarnation counter.
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

/// Build an honest validator (application, reporter, engine) and RETAIN its task
/// handles in a [`ManagedValidator`]. The storage partition is `validator.to_string()`,
/// matching the historical behavior of the dropped-handle path.
#[allow(clippy::too_many_arguments)]
pub fn build_validator<
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
    forwarding: ForwardPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> ManagedValidator<P, reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>>
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
    build_validator_with_reporter::<P, EC, _, _, _, _, _, _, _>(
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
        forwarding,
        partition,
        pending,
        recovered,
        resolver,
        certify,
        wiring,
    )
}

#[allow(clippy::too_many_arguments)]
fn start_validator_engine<
    P,
    EC,
    Automaton,
    Relay,
    R,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    context: &deterministic::Context,
    oracle: &Oracle<PublicKeyOf<P>, deterministic::Context>,
    scheme: P::Scheme,
    validator: PublicKeyOf<P>,
    elector: EC,
    automaton: Automaton,
    relay: Relay,
    reporter: R,
    partition: String,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    forwarding: ForwardPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
) -> Handle<()>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme> + Clone + Send + 'static,
    Automaton: CertifiableAutomaton<
            Context = SimplexContext<Sha256Digest, PublicKeyOf<P>>,
            Digest = Sha256Digest,
        > + Send
        + 'static,
    Relay: ConsensusRelay<
            Digest = Sha256Digest,
            PublicKey = PublicKeyOf<P>,
            Plan = Plan<PublicKeyOf<P>>,
        >,
    R: Reporter<Activity = Activity<P::Scheme, Sha256Digest>>,
    PendingSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    PendingReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    RecoveredSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    RecoveredReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
    ResolverSender: commonware_p2p::Sender<PublicKey = PublicKeyOf<P>>,
    ResolverReceiver: commonware_p2p::Receiver<PublicKey = PublicKeyOf<P>>,
{
    let (vote_sender, vote_receiver) = pending;
    let (certificate_sender, certificate_receiver) = recovered;
    let (resolver_sender, resolver_receiver) = resolver;

    let engine_cfg = config::Config {
        blocker: oracle.control(validator),
        scheme,
        elector,
        automaton,
        relay,
        reporter,
        partition,
        mailbox_size,
        epoch: Epoch::new(EPOCH),
        floor: Floor::Genesis(application::genesis::<Sha256>(Epoch::new(EPOCH))),
        leader_timeout,
        certification_timeout,
        timeout_retry: Duration::from_secs(10),
        fetch_timeout: Duration::from_secs(1),
        view_retention: Delta::new(10),
        skip: SkipPolicy::Enabled {
            timeout: Duration::from_secs(11),
            budget: SkipBudget::Participants,
        },
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
        forward: forwarding,
        track_historical_votes: false,
    };
    let engine = Engine::new(context.child("engine"), engine_cfg);
    engine.start(
        (vote_sender, vote_receiver),
        (certificate_sender, certificate_receiver),
        (resolver_sender, resolver_receiver),
    )
}

/// A reporter family the managed-validator builder can instantiate: how a
/// fresh instance is constructed and which automaton the engine drives. The
/// mock family runs the application directly; the recording family wraps it
/// in its audit-history recorder.
pub trait HarnessReporter<P, EC, Mailbox>:
    Reporter<Activity = Activity<P::Scheme, Sha256Digest>> + Clone
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    type Automaton: CertifiableAutomaton<
            Context = SimplexContext<Sha256Digest, PublicKeyOf<P>>,
            Digest = Sha256Digest,
        > + Send
        + 'static;

    fn create(
        context: deterministic::Context,
        observer: PublicKeyOf<P>,
        config: reporter::Config<P::Scheme, EC>,
    ) -> Self;

    fn automaton(&self, context: &deterministic::Context, application: Mailbox) -> Self::Automaton;
}

impl<P, EC> HarnessReporter<P, EC, application::Mailbox<Sha256Digest, PublicKeyOf<P>>>
    for reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    type Automaton = application::Mailbox<Sha256Digest, PublicKeyOf<P>>;

    fn create(
        context: deterministic::Context,
        _observer: PublicKeyOf<P>,
        config: reporter::Config<P::Scheme, EC>,
    ) -> Self {
        Self::new(context, config)
    }

    fn automaton(
        &self,
        _context: &deterministic::Context,
        application: application::Mailbox<Sha256Digest, PublicKeyOf<P>>,
    ) -> Self::Automaton {
        application
    }
}

impl<P, EC> HarnessReporter<P, EC, block_relay::Mailbox<PublicKeyOf<P>>>
    for reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    type Automaton = block_relay::Mailbox<PublicKeyOf<P>>;

    fn create(
        context: deterministic::Context,
        _observer: PublicKeyOf<P>,
        config: reporter::Config<P::Scheme, EC>,
    ) -> Self {
        Self::new(context, config)
    }

    fn automaton(
        &self,
        _context: &deterministic::Context,
        application: block_relay::Mailbox<PublicKeyOf<P>>,
    ) -> Self::Automaton {
        application
    }
}

impl<P, EC> HarnessReporter<P, EC, application::Mailbox<Sha256Digest, PublicKeyOf<P>>>
    for RecordingReporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    type Automaton = RecordingAutomaton<
        deterministic::Context,
        application::Mailbox<Sha256Digest, PublicKeyOf<P>>,
        P::Scheme,
        Sha256Digest,
    >;

    fn create(
        context: deterministic::Context,
        observer: PublicKeyOf<P>,
        config: reporter::Config<P::Scheme, EC>,
    ) -> Self {
        Self::new(context, observer, 0, config)
    }

    fn automaton(
        &self,
        context: &deterministic::Context,
        application: application::Mailbox<Sha256Digest, PublicKeyOf<P>>,
    ) -> Self::Automaton {
        RecordingAutomaton::new(
            context.child("automaton_recorder"),
            application,
            self.audit(),
        )
    }
}

impl<P, EC> HarnessReporter<P, EC, block_relay::Mailbox<PublicKeyOf<P>>>
    for RecordingReporter<deterministic::Context, P::Scheme, EC, Sha256Digest>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme>,
{
    type Automaton = RecordingAutomaton<
        deterministic::Context,
        block_relay::Mailbox<PublicKeyOf<P>>,
        P::Scheme,
        Sha256Digest,
    >;

    fn create(
        context: deterministic::Context,
        observer: PublicKeyOf<P>,
        config: reporter::Config<P::Scheme, EC>,
    ) -> Self {
        Self::new(context, observer, 0, config)
    }

    fn automaton(
        &self,
        context: &deterministic::Context,
        application: block_relay::Mailbox<PublicKeyOf<P>>,
    ) -> Self::Automaton {
        RecordingAutomaton::new(
            context.child("automaton_recorder"),
            application,
            self.audit(),
        )
    }
}

/// [`build_validator`] with an explicit reporter and storage partition. The
/// reporter family `R` decides construction and the engine automaton (see
/// [`HarnessReporter`]). When `existing` is `Some`, that reporter instance is
/// reused (rather than a fresh one created) so a durable restart RETAINS the
/// pre-crash safety history whose Arc-backed maps survived the abort. The
/// public build paths pass `None` and the default `validator.to_string()`
/// partition; a durable restart passes the crashed validator's reporter and
/// its unchanged partition.
#[allow(clippy::too_many_arguments)]
pub fn build_validator_with_reporter<
    P,
    EC,
    R,
    PendingSender,
    PendingReceiver,
    RecoveredSender,
    RecoveredReceiver,
    ResolverSender,
    ResolverReceiver,
>(
    existing: Option<R>,
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
    forwarding: ForwardPolicy,
    partition: String,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> ManagedValidator<P, R>
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme> + Clone + Send + 'static,
    R: HarnessReporter<P, EC, application::Mailbox<Sha256Digest, PublicKeyOf<P>>>,
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
            R::create(context.child("reporter"), validator.clone(), reporter_cfg)
        }
    };

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
    let automaton = reporter.automaton(&context, application.clone());

    let stored_scheme = scheme.clone();
    let engine_handle = start_validator_engine::<P, EC, _, _, _, _, _, _, _, _, _>(
        &context,
        oracle,
        scheme,
        validator.clone(),
        elector,
        automaton,
        application.clone(),
        wiring.wire(reporter.clone()),
        partition.clone(),
        leader_timeout,
        certification_timeout,
        mailbox_size,
        forwarding,
        pending,
        recovered,
        resolver,
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

/// Spawn an honest validator backed by the fuzz-local filterable block relay.
#[allow(clippy::too_many_arguments)]
pub fn spawn_filtered_honest_validator<
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
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    forwarding: ForwardPolicy,
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
    spawn_filtered_validator_with_reporter::<
        P,
        EC,
        reporter::Reporter<deterministic::Context, P::Scheme, EC, Sha256Digest>,
        _,
        _,
        _,
        _,
        _,
        _,
    >(
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
        forwarding,
        pending,
        recovered,
        resolver,
        certify,
        wiring,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_filtered_validator_with_reporter<
    P,
    EC,
    R,
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
    relay: Arc<block_relay::Relay<PublicKeyOf<P>>>,
    leader_timeout: Duration,
    certification_timeout: Duration,
    mailbox_size: NonZeroUsize,
    forwarding: ForwardPolicy,
    pending: (PendingSender, PendingReceiver),
    recovered: (RecoveredSender, RecoveredReceiver),
    resolver: (ResolverSender, ResolverReceiver),
    certify: CertifyChoice,
    wiring: ReporterWiring,
) -> R
where
    P: simplex::Simplex,
    EC: ElectorConfig<P::Scheme> + Clone + Send + 'static,
    R: HarnessReporter<P, EC, block_relay::Mailbox<PublicKeyOf<P>>>,
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
    let reporter = R::create(context.child("reporter"), validator.clone(), reporter_cfg);

    let validator_idx = participants
        .iter()
        .position(|p| p == &validator)
        .expect("validator must be in participants");
    let app_cfg = block_relay::Config::<_> {
        relay,
        me: validator.clone(),
        propose_latency: (10.0, 5.0),
        verify_latency: (10.0, 5.0),
        certify_latency: (10.0, 5.0),
        should_certify: certify.into_certifier(validator_idx),
    };
    let (actor, application) = block_relay::Application::new(context.child("application"), app_cfg);
    let _app_handle = actor.start();
    let automaton = reporter.automaton(&context, application.clone());

    let partition = validator.to_string();
    let _engine_handle = start_validator_engine::<P, EC, _, _, _, _, _, _, _, _, _>(
        &context,
        oracle,
        scheme,
        validator,
        elector,
        automaton,
        application.clone(),
        wiring.wire(reporter.clone()),
        partition,
        leader_timeout,
        certification_timeout,
        mailbox_size,
        forwarding,
        pending,
        recovered,
        resolver,
    );

    reporter
}

/// Default link used by the round-indexed fault scheduler when re-establishing edges.
pub fn default_link() -> Link {
    Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    }
}

pub fn scheduled_partition(
    schedule: &[(View, SetPartition)],
    executing_view: u64,
) -> Option<SetPartition> {
    schedule
        .iter()
        .find_map(|(view, p)| (*view == View::new(executing_view)).then_some(*p))
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

pub async fn spawn_network_fault_scheduler<P, R>(
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

pub fn network_faults(
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

pub type TwinsElector<P> = twins::Elector<<P as simplex::Simplex>::Elector>;

/// Observation retained for one Twins engine. Existing Twins targets use the
/// summary variant; dedicated audit targets use the recording variant only for
/// correct engines.
pub enum TwinsReporter<P>
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
    pub fn summary(
        &self,
    ) -> reporter::Reporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest> {
        match self {
            Self::Summary(reporter) => reporter.clone(),
            Self::Recording(reporter) => reporter.inner().clone(),
        }
    }

    pub fn recording(
        &self,
    ) -> Option<RecordingReporter<deterministic::Context, P::Scheme, TwinsElector<P>, Sha256Digest>>
    {
        match self {
            Self::Summary(_) => None,
            Self::Recording(reporter) => Some(reporter.clone()),
        }
    }

    pub async fn subscribe(&mut self) -> (View, Receiver<View>) {
        match self {
            Self::Summary(reporter) => reporter.subscribe().await,
            Self::Recording(reporter) => reporter.subscribe().await,
        }
    }
}

/// Network and stack state prepared by a [`TwinsBackend`].
pub struct TwinsSetup<P: simplex::Simplex, S> {
    pub oracle: Oracle<PublicKeyOf<P>, deterministic::Context>,
    pub participants: Vec<PublicKeyOf<P>>,
    pub schemes: Vec<P::Scheme>,
    pub registrations: HashMap<PublicKeyOf<P>, NetworkChannels<PublicKeyOf<P>>>,
    pub state: S,
}

/// One selected Twins scenario plus backend-specific case metadata.
pub struct TwinsCase<C> {
    pub scenario: twins::Scenario,
    pub compromised: Vec<usize>,
    pub data: C,
}

/// Shared topology passed to every stack-specific Twins hook.
pub struct TwinsTopology<P: simplex::Simplex, C> {
    pub scenario: twins::Scenario,
    pub compromised: HashSet<usize>,
    pub elector: TwinsElector<P>,
    pub term_length: TermLength,
    #[cfg_attr(not(feature = "mocks"), allow(dead_code))]
    pub data: C,
}

/// Configuration for a secondary twin implemented by the existing Disrupter.
#[derive(Clone, Copy)]
pub struct TwinsDisrupter {
    pub strategy: StrategyChoice,
    pub required_containers: u64,
    pub epoch: Epoch,
}

/// Stack-specific hooks for the shared Twins topology driver.
///
/// The driver owns scenario generation, compromised-node iteration, channel
/// splitting/routing, twin role dispatch, Disrupter startup, and honest-node
/// iteration. A backend owns its network/validator stack, engine construction,
/// liveness observation, and final invariants.
pub trait TwinsBackend<P: simplex::Simplex> {
    type State;
    type Case;
    type Digest: commonware_cryptography::Digest;

    fn setup(
        &mut self,
        context: &mut deterministic::Context,
    ) -> impl std::future::Future<Output = TwinsSetup<P, Self::State>> + Send;

    fn term_length(&self) -> TermLength;

    /// Select the framework whose cases the shared driver will generate.
    fn framework(&mut self, rng: &mut FuzzRng, participants: usize) -> twins::Framework;

    /// Select one generated case and attach backend-specific metadata.
    fn select_case(
        &mut self,
        rng: &mut FuzzRng,
        participants: &[PublicKeyOf<P>],
        cases: Vec<twins::Case>,
    ) -> Option<TwinsCase<Self::Case>>;

    /// Called after case selection and before any twin half is spawned.
    fn configure_topology(
        &mut self,
        _state: &mut Self::State,
        _topology: &TwinsTopology<P, Self::Case>,
        _participants: &Arc<[PublicKeyOf<P>]>,
    ) {
    }

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

    /// Return a filterable block relay for a Disrupter-backed secondary half.
    fn disrupter_block_relay(
        &self,
        _state: &Self::State,
    ) -> Option<Arc<block_relay::Relay<PublicKeyOf<P>>>> {
        None
    }

    /// Sender tag for block broadcasts emitted by a Disrupter-backed twin half.
    fn disrupter_block_relay_tag(&self) -> Option<u64> {
        None
    }

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
pub async fn run_twins_with_backend<P, B>(
    context: &mut deterministic::Context,
    backend: &mut B,
    entropy: Vec<u8>,
) where
    P: simplex::Simplex,
    B: TwinsBackend<P>,
{
    let mut setup = backend.setup(context).await;
    let participants: Arc<[PublicKeyOf<P>]> = setup.participants.into();
    let term_length = backend.term_length();
    let mut scenario_rng = FuzzRng::new(entropy);
    let framework = backend.framework(&mut scenario_rng, participants.len());
    let cases = twins::cases(&mut scenario_rng, framework);
    let Some(case) = backend.select_case(&mut scenario_rng, participants.as_ref(), cases) else {
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
        elector: twins::Elector::new(
            P::elector(term_length, PINNED_OPTIMISTIC_VIEWS),
            &case.scenario,
            participants.len(),
        ),
        scenario: case.scenario,
        compromised,
        term_length,
        data: case.data,
    };
    backend.configure_topology(&mut setup.state, &topology, &participants);

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
            vote_sender.split_with(twins_network::vote_forwarder::<P, B::Digest>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
            ));
        let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
            node_context.child("vote_split"),
            twins_network::vote_router::<P, B::Digest>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
            ),
        );
        let (certificate_sender_primary, certificate_sender_secondary) = certificate_sender
            .split_with(twins_network::certificate_forwarder::<P, B::Digest>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
                scheme.clone(),
            ));
        let (certificate_receiver_primary, certificate_receiver_secondary) = certificate_receiver
            .split_with(
                node_context.child("certificate_split"),
                twins_network::certificate_router::<P, B::Digest>(
                    participants.clone(),
                    topology.scenario.clone(),
                    term_length,
                    scheme.clone(),
                ),
            );
        let (resolver_sender_primary, resolver_sender_secondary) =
            resolver_sender.split_with(twins_network::resolver_forwarder::<P, B::Digest>(
                participants.clone(),
                topology.scenario.clone(),
                term_length,
                scheme.clone(),
            ));
        let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
            .split_with(
                node_context.child("resolver_split"),
                twins_network::resolver_router::<P, B::Digest>(
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
            start_disrupter_with_epoch_relay_and_tag::<P>(
                node_context.child("secondary"),
                scheme,
                &disrupter.strategy,
                disrupter.required_containers,
                disrupter.epoch,
                (vote_sender_secondary, vote_receiver_secondary),
                (certificate_sender_secondary, certificate_receiver_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
                backend.disrupter_block_relay(&setup.state),
                backend.disrupter_block_relay_tag(),
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

/// Selector for which a fuzz harness will dispatch to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Standard,
    TwinsMutator,
    TwinsCampaign,
    FaultyNet,
    Byzzfuzz,
    MalloryContainer,
    Chaos,
    ChaosTwins,
}

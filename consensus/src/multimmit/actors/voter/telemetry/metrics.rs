//! Metrics registered by the voter.

use crate::multimmit::{
    actors::metrics::{COUNT_POW2_FROM_ZERO, STAGE_LATENCY, Traffic, WAN_LATENCY, plane_counter},
    machine::{
        CoreProgress, DeclarationContext, DeclarationContexts, DeclarationCounts, DeclarationRule,
        InputKind, Lane, ObservationStatus, PinnedUndetermined, ProductionHolds, ProtocolComponent,
        Refusals, Rejection, ViewEnd, ViewEnds,
    },
    types::{Activity, Artifact, ArtifactKind, Resolution},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, Gauge, Histogram,
        MetricsExt as _, histogram,
    },
};
use std::time::Duration;

/// Where a view proof entered the voter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum ViewProofSource {
    /// Gossip from a peer.
    Network,
    /// A resolver fetch the machine requested.
    Resolver,
}

/// The kind of certificate a view proof carries.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum ViewProofKind {
    /// A V-QC.
    Vqc,
    /// An L-QC.
    Lqc,
}

impl ViewProofKind {
    /// Returns the kind of view proof `artifact` carries, or `None` for other artifacts.
    pub(crate) const fn of<V: Variant, D: Digest>(artifact: &Artifact<V, D>) -> Option<Self> {
        match artifact {
            Artifact::Vqc(_) => Some(Self::Vqc),
            Artifact::Lqc(_) => Some(Self::Lqc),
            _ => None,
        }
    }
}

/// How the machine classified a view proof before verification.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum ViewProofAdmissionOutcome {
    /// Scheduled for verification.
    Scheduled,
    /// Already known.
    Duplicate,
    /// Rejected because the artifact cache was full.
    ArtifactCacheFull,
    /// Rejected because every verification job slot was taken.
    VerificationJobsFull,
    /// Rejected for any other reason.
    OtherRejected,
}

impl From<ObservationStatus> for ViewProofAdmissionOutcome {
    fn from(status: ObservationStatus) -> Self {
        match status {
            ObservationStatus::Scheduled => Self::Scheduled,
            ObservationStatus::Duplicate => Self::Duplicate,
            ObservationStatus::Rejected(Rejection::ArtifactCacheFull) => Self::ArtifactCacheFull,
            ObservationStatus::Rejected(Rejection::VerificationJobsFull) => {
                Self::VerificationJobsFull
            }
            ObservationStatus::Rejected(_) => Self::OtherRejected,
        }
    }
}

/// Label set of the view-proof admission counter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ViewProofAdmission {
    /// Where the proof entered.
    pub(crate) source: ViewProofSource,
    /// The certificate the proof carries.
    pub(crate) kind: ViewProofKind,
    /// How the machine classified it.
    pub(crate) outcome: ViewProofAdmissionOutcome,
}

impl ViewProofAdmission {
    const SOURCES: [ViewProofSource; 2] = [ViewProofSource::Network, ViewProofSource::Resolver];
    const KINDS: [ViewProofKind; 2] = [ViewProofKind::Vqc, ViewProofKind::Lqc];
    const OUTCOMES: [ViewProofAdmissionOutcome; 5] = [
        ViewProofAdmissionOutcome::Scheduled,
        ViewProofAdmissionOutcome::Duplicate,
        ViewProofAdmissionOutcome::ArtifactCacheFull,
        ViewProofAdmissionOutcome::VerificationJobsFull,
        ViewProofAdmissionOutcome::OtherRejected,
    ];
}

/// Why this node's final vote for a view was sent, as a metric label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum ViewEndReason {
    /// Every chain filled its window.
    Count,
    /// `t_max` passed and rule (iii) declared the chains short of their window.
    Bound,
    /// Another declaration rule declared at least one chain.
    Declared,
}

impl ViewEndReason {
    const ALL: [(Self, ViewEnd); 3] = [
        (Self::Count, ViewEnd::Count),
        (Self::Bound, ViewEnd::Bound),
        (Self::Declared, ViewEnd::Declared),
    ];
}

/// Label set of the view-end counter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ViewEndLabel {
    pub(crate) reason: ViewEndReason,
}

/// The rule that declared a chain final, as a metric label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum DeclarationRuleLabel {
    /// Rule (i): no sign of life for `D_stop`.
    Stopped,
    /// Rule (ii): neither capped nor declared `t_late` after all but `f` chains were.
    Late,
    /// Rule (iii): `t_max` passed.
    Bound,
    /// Rule (iv): a V-QC of the view arrived first.
    ViewChange,
    /// Rule (v): first binding votes split the chain.
    Split,
    /// Optimisation (A): the grace passed without a valid proposal.
    Grace,
    /// Optimisation (B): the leader was silent at entry.
    SilentLeader,
}

impl DeclarationRuleLabel {
    const ALL: [(Self, DeclarationRule); 7] = [
        (Self::Stopped, DeclarationRule::Stopped),
        (Self::Late, DeclarationRule::Late),
        (Self::Bound, DeclarationRule::Bound),
        (Self::ViewChange, DeclarationRule::ViewChange),
        (Self::Split, DeclarationRule::Split),
        (Self::Grace, DeclarationRule::Grace),
        (Self::SilentLeader, DeclarationRule::SilentLeader),
    ];
}

/// Label set of the declaration counter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct DeclarationLabel {
    pub(crate) rule: DeclarationRuleLabel,
}

/// Label set of the declaration-context counter: the rule, and what this node knew about the
/// chain when it declared it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct DeclarationContextLabel {
    pub(crate) rule: DeclarationRuleLabel,
    /// This node's tip on the chain was capped.
    pub(crate) capped: bool,
    /// No sign of life had arrived from the chain for `D_stop`.
    pub(crate) silent: bool,
    /// The acceptance bounds held back a ready header of the chain.
    pub(crate) held_back: bool,
}

/// Why final votes of a view left a chain undetermined, as a metric label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum UndeterminedCause {
    /// Too few of the votes' tips resolve to locally held headers.
    Unresolved,
    /// Enough tips resolve, but no `n - f` of them reach the same block.
    Split,
}

/// Label set of the undetermined-chain counter.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct UndeterminedLabel {
    pub(crate) cause: UndeterminedCause,
}

impl DeclarationContextLabel {
    const fn new(rule: DeclarationRuleLabel, context: DeclarationContext) -> Self {
        Self {
            rule,
            capped: context.capped,
            silent: context.silent,
            held_back: context.held_back,
        }
    }
}

/// The machine's cumulative telemetry counters, which the voter exports as counter increments.
///
/// Every count is cumulative since the machine started; a count below its earlier value (a fresh
/// machine) adds nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cumulative {
    pub(crate) ends: ViewEnds,
    pub(crate) declarations: DeclarationCounts,
    pub(crate) contexts: DeclarationContexts,
    pub(crate) refusals: Refusals,
    pub(crate) pinned_undetermined: PinnedUndetermined,
    pub(crate) production_holds: ProductionHolds,
}

impl From<&CoreProgress> for Cumulative {
    fn from(progress: &CoreProgress) -> Self {
        Self {
            ends: progress.view_ends,
            declarations: progress.declarations,
            contexts: progress.declaration_contexts,
            refusals: progress.refusals,
            pinned_undetermined: progress.pinned_undetermined,
            production_holds: progress.production_holds,
        }
    }
}

/// Returns the increment from cumulative count `earlier` to `now`, zero for a fresh machine.
const fn since(earlier: u64, now: u64) -> u64 {
    now.saturating_sub(earlier)
}

/// Registers a counter family labelled by artifact kind, exporting every kind from zero.
fn artifact_counter<E: MetricsTrait>(
    context: &E,
    name: &'static str,
    help: &'static str,
) -> CounterFamily<ArtifactTraffic> {
    let family = context.family(name, help);
    for artifact in ArtifactLabel::ALL {
        let _ = family.get_or_create(&ArtifactTraffic { artifact });
    }
    family
}


/// The kind of artifact one transmission carries, as a metric label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(crate) enum ArtifactLabel {
    /// A producer-signed transaction-block header.
    Header,
    /// A leader proposal.
    Proposal,
    /// A vote update.
    Update,
    /// A V-QC.
    Vqc,
    /// An L-QC.
    Lqc,
    /// A finalization certificate with its opening.
    Floor,
}

impl ArtifactLabel {
    const ALL: [Self; 6] = [
        Self::Header,
        Self::Proposal,
        Self::Update,
        Self::Vqc,
        Self::Lqc,
        Self::Floor,
    ];
}

impl From<ArtifactKind> for ArtifactLabel {
    fn from(kind: ArtifactKind) -> Self {
        match kind {
            ArtifactKind::TransactionBlock => Self::Header,
            ArtifactKind::LeaderBlock => Self::Proposal,
            ArtifactKind::Update => Self::Update,
            ArtifactKind::Vqc => Self::Vqc,
            ArtifactKind::Lqc => Self::Lqc,
            ArtifactKind::Floor => Self::Floor,
        }
    }
}

/// Label set of the per-artifact traffic counters.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(crate) struct ArtifactTraffic {
    pub(crate) artifact: ArtifactLabel,
}

/// Returns the metric label of a core input kind.
const fn input_label(kind: InputKind) -> &'static str {
    match kind {
        InputKind::Lifecycle => "lifecycle",
        InputKind::Observe => "observe",
        InputKind::Verified => "verified",
        InputKind::Persisted => "persisted",
        InputKind::EffectCompleted => "effect_completed",
        InputKind::Tick => "tick",
        InputKind::BlockBuilt => "block_built",
        InputKind::BlockCustodied => "block_custodied",
        InputKind::Validated => "validated",
        InputKind::ResolutionCompleted => "resolution_completed",
        InputKind::Crypto => "crypto",
    }
}

/// Returns the metric label of a core input lane.
const fn lane_label(lane: Lane) -> &'static str {
    match lane {
        Lane::PersistenceCompletion => "persistence",
        Lane::LocalCompletion => "local",
        Lane::Timer => "timer",
        Lane::ResolverResult => "resolver",
        Lane::PeerObservation => "observation",
    }
}

/// Returns the metric label of a machine work quantum: the component it drove, or
/// `completion` for a quantum that only completed issued signing or aggregation work.
const fn work_label(component: Option<ProtocolComponent>) -> &'static str {
    match component {
        Some(ProtocolComponent::Chain) => "chain",
        Some(ProtocolComponent::Producer) => "producer",
        Some(ProtocolComponent::View) => "view",
        Some(ProtocolComponent::Pool) => "pool",
        Some(ProtocolComponent::Emission) => "emission",
        Some(ProtocolComponent::Forwarding) => "forwarding",
        Some(ProtocolComponent::Retention) => "retention",
        None => "completion",
    }
}

/// Index of a work quantum's histogram in [`ServiceMetrics::work`].
const fn work_index(component: Option<ProtocolComponent>) -> usize {
    match component {
        Some(component) => component as usize,
        None => ProtocolComponent::COUNT,
    }
}

/// Where the voter thread's time goes, per unit of core service.
///
/// Each histogram is keyed by a bounded label, so the voter's busy time decomposes into input
/// kinds and machine components, and queueing inside the core separates from network delay.
#[derive(Clone)]
pub(crate) struct ServiceMetrics {
    /// `input_processing{kind}`: seconds the voter spent on one core step applying an input and
    /// executing its capabilities.
    input: Vec<Histogram>,
    /// `work_processing{component}`: seconds the voter spent on one machine work quantum and
    /// its capabilities, by the component it drove.
    work: Vec<Histogram>,
    /// `input_wait{lane}`: seconds from an input's admission into the core to the step that
    /// completes it.
    wait: Vec<Histogram>,
}

impl ServiceMetrics {
    fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            input: InputKind::ALL
                .into_iter()
                .map(|kind| {
                    context
                        .child("input")
                        .with_attribute("kind", input_label(kind))
                        .histogram(
                            "processing",
                            "seconds the voter spent on one core step applying an input",
                            histogram::Buckets::LOCAL,
                        )
                })
                .collect(),
            work: ProtocolComponent::ALL
                .into_iter()
                .map(Some)
                .chain([None])
                .map(|component| {
                    context
                        .child("work")
                        .with_attribute("component", work_label(component))
                        .histogram(
                            "processing",
                            "seconds the voter spent on one machine work quantum",
                            histogram::Buckets::LOCAL,
                        )
                })
                .collect(),
            wait: Lane::ALL
                .into_iter()
                .map(|lane| {
                    context
                        .child("input")
                        .with_attribute("lane", lane_label(lane))
                        .histogram(
                            "wait",
                            "seconds from an input's admission into the core to the step completing it",
                            histogram::Buckets::LOCAL,
                        )
                })
                .collect(),
        }
    }

    /// Records one core step that applied an input of `kind`.
    pub(crate) fn input(&self, kind: InputKind, elapsed: Duration) {
        self.input[kind as usize].observe(elapsed.as_secs_f64());
    }

    /// Records one machine work quantum that drove `component`.
    pub(crate) fn work(&self, component: Option<ProtocolComponent>, elapsed: Duration) {
        self.work[work_index(component)].observe(elapsed.as_secs_f64());
    }

    /// Records the core queueing of an input on `lane` that waited `millis`.
    pub(crate) fn wait(&self, lane: Lane, millis: u64) {
        self.wait[lane.index()].observe(millis as f64 / 1_000.0);
    }
}

/// Per-producer-chain gauges.
///
/// This family scales with the producer chain count, which equals the validator count, so it
/// carries only the value that localizes a single stalled chain. Aggregate floors for the
/// remaining chain heights live on [`Metrics`].
#[derive(Clone)]
pub(crate) struct ChainMetrics {
    /// Final height of one producer chain, so a stalled chain is attributable to its producer.
    pub(crate) finalized: Gauge,
}

impl ChainMetrics {
    fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            finalized: context.gauge("finalized", "final producer height"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Metrics {
    /// Completions the machine discarded as stale; a sustained rate means wasted verification.
    pub(crate) stale: Counter,
    /// Fatal epoch failures. Any increment is an alarm.
    pub(crate) fatal: Counter,
    /// Outstanding durable publications under retry; growth means the transport is not draining.
    pub(crate) publications: Gauge,
    /// Journal events retained since the newest recovery base; sizes recovery replay work.
    pub(crate) retained_events: Gauge,
    /// Retained artifacts plus local reservations. The numerator of cache saturation.
    pub(crate) artifact_cache_occupancy: Gauge,
    /// Configured artifact cache capacity. The denominator of cache saturation.
    pub(crate) artifact_cache_capacity: Gauge,
    /// Artifact capacity still available to untrusted ingress; zero means peers are shut out.
    pub(crate) remote_artifact_capacity: Gauge,
    /// Artifact capacity still available to local work; zero wedges local protocol progress.
    pub(crate) local_artifact_capacity: Gauge,
    /// Verification jobs in flight. The numerator of verify-pool saturation.
    pub(crate) verification_jobs: Gauge,
    /// Configured verification-job capacity. The denominator of verify-pool saturation.
    pub(crate) verification_job_capacity: Gauge,
    /// Retained future-view artifacts; a full index starves re-anchoring view proofs.
    pub(crate) future_artifacts: Gauge,
    /// Current view. Flat means views have stopped advancing.
    pub(crate) current_view: Gauge,
    /// Retired view floor; its distance from the current view is retention depth.
    pub(crate) retired_view: Gauge,
    /// Newest view whose resolution facts were reported. Flat means resolution has stopped.
    pub(crate) last_resolved: Gauge,
    /// Height of the newest local header. Flat on a producer means local production has stalled.
    pub(crate) produced_blocks: Gauge,
    /// Local application build slot occupancy.
    pub(crate) build_active: Gauge,
    /// Local producer bodies entering validated durable custody.
    pub(crate) custody_active: Gauge,
    /// Per-chain final heights.
    pub(crate) chains: Vec<ChainMetrics>,
    /// Lowest locally accepted height across producer chains; the dissemination laggard.
    pub(crate) chain_accepted_floor: Gauge,
    /// Lowest height-quorum height across producer chains; the endorsement laggard.
    pub(crate) chain_quorum_floor: Gauge,
    /// Producer chains finalized below the highest finalized chain; the fan-out of a stall.
    pub(crate) lagging_chains: Gauge,
    /// Liveness deadlines reached. The primary liveness alarm.
    pub(crate) view_timeouts: Counter,
    /// Producer headers accepted by adoption, without a local body verdict. A sustained rate
    /// means bodies reach this node more slowly than endorsements do.
    pub(crate) adopted_headers: Counter,
    /// Views resolved by determination from `n - f` final votes, without an L-QC.
    pub(crate) views_determined: Counter,
    /// Views resolved by an L-QC pinning them.
    pub(crate) views_pinned: Counter,
    /// Microseconds the voter thread spent inside core service cycles. Its rate is the thread's
    /// busy fraction, the saturation signal for the single-threaded machine.
    pub(crate) busy_micros: Counter,
    /// Ingress hand-off to voter ingestion of one observation cohort. The mailbox queue on the
    /// round's critical path.
    pub(crate) observation_wait: Histogram,
    /// Whether the view deadline is armed. Zero with a flat view is a halted voter.
    pub(crate) view_timer_armed: Gauge,
    /// Self-certifying view proofs classified before verification; rejections are the wedge alarm.
    pub(crate) view_proof_admissions: CounterFamily<ViewProofAdmission>,
    /// Views this node sent its final vote for, by why the view ended. Healthy views end on
    /// count; a rising declared share means chains are being cut short.
    pub(crate) view_ends: CounterFamily<ViewEndLabel>,
    /// Summed milliseconds from entering each counted view to its final vote. Divided by the
    /// view-end rate, the mean view length.
    pub(crate) view_end_millis: Counter,
    /// Chains declared final, by declaration rule.
    pub(crate) declarations: CounterFamily<DeclarationLabel>,
    /// Chains declared final, by rule and by what this node knew about the chain: whether its
    /// tip was capped, whether the chain was silent for `D_stop`, and whether the acceptance
    /// bounds held back a ready header of it. Attributes declarations of live chains.
    pub(crate) declaration_contexts: CounterFamily<DeclarationContextLabel>,
    /// Summed milliseconds from each declared chain's latest sign of life to its declaration, by
    /// rule. Divided by the rule's declarations, the mean silence it acted on.
    pub(crate) declaration_silence_millis: CounterFamily<DeclarationLabel>,
    /// Ready peer headers whose acceptance the flow bound `D` refused, once per chain and
    /// height. Any sustained rate means `D` is too small for the lag between producers and this
    /// node, which also hides those chains' signs of life from declaration rule (i).
    pub(crate) flow_refusals: Counter,
    /// Ready peer headers whose acceptance the finality bound `D + N` refused, once per chain
    /// and height.
    pub(crate) finality_refusals: Counter,
    /// View boundaries pinned (case (a)) after `n - f` or more final votes of the view failed
    /// to determine them (case (b)).
    pub(crate) pinned_undetermined: Counter,
    /// Over those boundaries, the chains the final votes left undetermined, by cause.
    pub(crate) undetermined_chains: CounterFamily<UndeterminedLabel>,
    /// The measured one-way delay `delta_hat` the current view's timers use.
    pub(crate) delay_estimate: Gauge,
    /// The measured per-block production interval `theta_hat` the current view's timers use.
    pub(crate) production_estimate: Gauge,
    /// Summed milliseconds the local producer was due to build but held by the flow bound. Its
    /// rate is the share of time the bound idles the producer.
    pub(crate) production_hold_millis: Counter,
    /// Holds of the local producer that cost time. Divides the held milliseconds into a mean
    /// hold.
    pub(crate) production_holds: Counter,
    /// The current view's grace `t_grace`.
    pub(crate) grace: Gauge,
    /// Application blocks produced.
    pub(crate) builds: Counter,
    /// Application builds declined.
    pub(crate) build_declines: Counter,
    /// Application blocks rejected as invalid; a sustained rate means a misbehaving producer.
    pub(crate) invalid_blocks: Counter,
    /// Block validations the application ended without a verdict.
    pub(crate) unavailable_validations: Counter,
    /// Transaction-block relay broadcasts requested by durable publications.
    pub(crate) relay_attempts: Counter,
    /// Relay broadcasts rejected by a closed application endpoint; any increment is a defect.
    pub(crate) relay_closed: Counter,
    /// Protocol messages accepted by the network, by plane.
    pub(crate) transmissions: CounterFamily<Traffic>,
    /// Protocol bytes accepted by the network, by plane. Egress budget.
    pub(crate) transmitted_bytes: CounterFamily<Traffic>,
    /// Protocol bytes resent by publication retries, by plane. Retry waste.
    pub(crate) retransmitted_bytes: CounterFamily<Traffic>,
    /// Protocol messages accepted by the network, by artifact kind.
    pub(crate) artifact_transmissions: CounterFamily<ArtifactTraffic>,
    /// Protocol bytes accepted by the network, by artifact kind, retries included.
    pub(crate) artifact_transmitted_bytes: CounterFamily<ArtifactTraffic>,
    /// View latency. The consensus service objective.
    pub(crate) round_latency: Histogram,
    /// V-QC formation latency, from this node's view entry to its local assembly.
    pub(crate) vqc_latency: Histogram,
    /// L-QC formation latency, from this node's view entry to its local assembly.
    pub(crate) lqc_latency: Histogram,
    /// Application build latency; separates application cost from consensus cost.
    pub(crate) build_latency: Histogram,
    /// Application validation latency; separates application cost from consensus cost.
    pub(crate) validation_latency: Histogram,
    /// Encoded size of each locally assembled V-QC; the certificate-plane bandwidth driver.
    pub(crate) vqc_bytes: Histogram,
    /// Encoded size of each locally assembled L-QC.
    pub(crate) lqc_bytes: Histogram,
    /// Encoded size of each vote update this node publishes; the consensus-plane bandwidth
    /// driver.
    pub(crate) update_bytes: Histogram,
    /// Voter thread time per input kind and machine component, and core queueing per lane.
    pub(crate) service: ServiceMetrics,
    /// Queue wait of view-critical verification jobs. Rises before a straggler wedges.
    pub(crate) verification_wait_fast: Histogram,
    /// Queue wait of bulk verification jobs.
    pub(crate) verification_wait_bulk: Histogram,
    /// Queueing for workers through the voter applying the verdicts, of view-critical
    /// verification jobs.
    pub(crate) verification_dwell_fast: Histogram,
    /// Queueing for workers through the voter applying the verdicts, of bulk verification jobs.
    pub(crate) verification_dwell_bulk: Histogram,
    /// Views each valid vote update trails the current view when the voter applies its verdict.
    /// Peers that fall behind, and local verification backlog, show up as a growing upper tail.
    pub(crate) verified_vote_lag: Histogram,
    /// Critical-pool submission to worker entry for local signing.
    pub(crate) crypto_submit_wait_signing: Histogram,
    /// Critical-pool submission to worker entry for certificate assembly.
    pub(crate) crypto_submit_wait_aggregation: Histogram,
}

/// Byte-size buckets for encoded artifact histograms, up to the default V-QC size bound.
const ENCODED_BYTES: [f64; 17] = [
    64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0, 131072.0,
    262144.0, 524288.0, 1048576.0, 2097152.0, 4194304.0,
];

impl Metrics {
    pub(crate) fn new<E: MetricsTrait>(context: &E, chain_count: usize) -> Self {
        Self {
            stale: context.counter("stale", "stale completions observed by the machine"),
            fatal: context.counter("fatal", "fatal epoch failures"),
            publications: context.gauge(
                "publications",
                "outstanding durable publications under retry",
            ),
            retained_events: context.gauge(
                "retained_events",
                "journal events retained since the newest recovery base",
            ),
            artifact_cache_occupancy: context.gauge(
                "artifact_cache_occupancy",
                "retained artifacts plus local protocol reservations",
            ),
            artifact_cache_capacity: context.gauge(
                "artifact_cache_capacity",
                "configured artifact cache capacity, the denominator of cache saturation",
            ),
            remote_artifact_capacity: context.gauge(
                "remote_artifact_capacity",
                "artifact capacity available to untrusted non-proof ingress",
            ),
            local_artifact_capacity: context.gauge(
                "local_artifact_capacity",
                "artifact capacity available to locally authorized non-proof work",
            ),
            verification_jobs: context
                .gauge("verification_jobs", "machine verification jobs in flight"),
            verification_job_capacity: context.gauge(
                "verification_job_capacity",
                "configured verification-job capacity, the denominator of pool saturation",
            ),
            future_artifacts: context.gauge("future_artifacts", "retained future-view artifacts"),
            current_view: context.gauge("current_view", "current view"),
            retired_view: context.gauge("retired_view", "retired view floor"),
            last_resolved: context.gauge(
                "last_resolved",
                "newest view whose resolution facts were reported",
            ),
            produced_blocks: context.gauge("produced_blocks", "height of the newest local header"),
            build_active: context.gauge("build_active", "local application build slot occupancy"),
            custody_active: context.gauge(
                "custody_active",
                "local producer bodies entering validated durable custody",
            ),
            chains: (0..chain_count)
                .map(|chain| {
                    let chain_context = context.child("chains").with_attribute("chain", chain);
                    ChainMetrics::new(&chain_context)
                })
                .collect(),
            chain_accepted_floor: context.gauge(
                "chain_accepted_floor",
                "lowest locally accepted height across producer chains",
            ),
            chain_quorum_floor: context.gauge(
                "chain_quorum_floor",
                "lowest height-quorum height across producer chains",
            ),
            lagging_chains: context.gauge(
                "lagging_chains",
                "producer chains finalized below the highest finalized chain",
            ),
            view_timeouts: context.counter("view_timeouts", "liveness deadlines reached"),
            adopted_headers: context.counter(
                "adopted_headers",
                "producer headers accepted by adoption without a local body verdict",
            ),
            views_determined: context.counter(
                "views_determined",
                "views resolved by determination from n-f final votes without an L-QC",
            ),
            views_pinned: context.counter("views_pinned", "views resolved by an L-QC pinning them"),
            observation_wait: context.histogram(
                "observation_wait",
                "ingress hand-off to voter ingestion of one observation cohort",
                STAGE_LATENCY,
            ),
            busy_micros: context.counter(
                "busy_micros",
                "microseconds the voter thread spent inside core service cycles",
            ),
            view_timer_armed: context.gauge(
                "view_timer_armed",
                "whether the current view deadline is armed",
            ),
            view_proof_admissions: {
                let view_proof_admissions = context.family(
                    "view_proof_admissions",
                    "self-certifying view proofs classified before verification",
                );
                for source in ViewProofAdmission::SOURCES {
                    for kind in ViewProofAdmission::KINDS {
                        for outcome in ViewProofAdmission::OUTCOMES {
                            let _ = view_proof_admissions.get_or_create(&ViewProofAdmission {
                                source,
                                kind,
                                outcome,
                            });
                        }
                    }
                }
                view_proof_admissions
            },
            view_ends: {
                let view_ends = context.family(
                    "view_ends",
                    "views this node sent its final vote for, by why the view ended",
                );
                for (reason, _) in ViewEndReason::ALL {
                    let _ = view_ends.get_or_create(&ViewEndLabel { reason });
                }
                view_ends
            },
            view_end_millis: context.counter(
                "view_end_millis",
                "summed milliseconds from view entry to this node's final vote",
            ),
            declarations: {
                let declarations =
                    context.family("declarations", "chains declared final, by declaration rule");
                for (rule, _) in DeclarationRuleLabel::ALL {
                    let _ = declarations.get_or_create(&DeclarationLabel { rule });
                }
                declarations
            },
            declaration_contexts: {
                let contexts = context.family(
                    "declaration_contexts",
                    "chains declared final, by rule, capped tip, silence for D_stop, and held-back header",
                );
                for (rule, _) in DeclarationRuleLabel::ALL {
                    for declared in DeclarationContext::ALL {
                        let _ = contexts.get_or_create(&DeclarationContextLabel::new(rule, declared));
                    }
                }
                contexts
            },
            declaration_silence_millis: {
                let silence = context.family(
                    "declaration_silence_millis",
                    "summed milliseconds from each declared chain's latest sign of life to its declaration, by rule",
                );
                for (rule, _) in DeclarationRuleLabel::ALL {
                    let _ = silence.get_or_create(&DeclarationLabel { rule });
                }
                silence
            },
            flow_refusals: context.counter(
                "flow_refusals",
                "ready peer headers refused by the flow bound D, once per chain and height",
            ),
            finality_refusals: context.counter(
                "finality_refusals",
                "ready peer headers refused by the finality bound D + N, once per chain and height",
            ),
            pinned_undetermined: context.counter(
                "pinned_undetermined",
                "view boundaries pinned after n-f or more final votes failed to determine them",
            ),
            undetermined_chains: {
                let undetermined = context.family(
                    "undetermined_chains",
                    "chains left undetermined at boundaries pinned after a failed determination, by cause",
                );
                for cause in [UndeterminedCause::Unresolved, UndeterminedCause::Split] {
                    let _ = undetermined.get_or_create(&UndeterminedLabel { cause });
                }
                undetermined
            },
            delay_estimate: context.gauge(
                "delay_estimate_milliseconds",
                "measured one-way delay delta_hat used by the current view's timers",
            ),
            production_estimate: context.gauge(
                "production_estimate_milliseconds",
                "measured per-block production interval theta_hat used by the current view's timers",
            ),
            production_hold_millis: context.counter(
                "production_hold_millis",
                "summed milliseconds the local producer was due to build but held by the flow bound",
            ),
            production_holds: context.counter(
                "production_holds",
                "holds of the local producer by the flow bound that cost time",
            ),
            grace: context.gauge("grace_milliseconds", "current view's grace t_grace"),
            builds: context.counter("builds", "application blocks produced"),
            build_declines: context.counter("build_declines", "application builds declined"),
            invalid_blocks: context.counter("invalid_blocks", "application blocks rejected"),
            unavailable_validations: context.counter(
                "unavailable_validations",
                "block validations the application ended without a verdict",
            ),
            relay_attempts: context.counter(
                "relay_attempts",
                "transaction-block Relay broadcasts requested by durable publications",
            ),
            relay_closed: context.counter(
                "relay_closed",
                "transaction-block Relay broadcasts rejected by a closed application endpoint",
            ),
            transmissions: plane_counter(
                context,
                "transmissions",
                "protocol messages accepted by the network by plane",
            ),
            transmitted_bytes: plane_counter(
                context,
                "transmitted_bytes",
                "protocol bytes accepted by the network by plane",
            ),
            retransmitted_bytes: plane_counter(
                context,
                "retransmitted_bytes",
                "protocol bytes accepted by the network for publication retries, by plane",
            ),
            artifact_transmissions: artifact_counter(
                context,
                "artifact_transmissions",
                "protocol messages accepted by the network, by artifact kind",
            ),
            artifact_transmitted_bytes: artifact_counter(
                context,
                "artifact_transmitted_bytes",
                "protocol bytes accepted by the network, by artifact kind, retries included",
            ),
            round_latency: context.histogram("round_latency", "view latency", WAN_LATENCY),
            vqc_latency: context.histogram(
                "vqc_latency",
                "V-QC formation latency from view entry to local assembly",
                WAN_LATENCY,
            ),
            lqc_latency: context.histogram(
                "lqc_latency",
                "L-QC formation latency from view entry to local assembly",
                WAN_LATENCY,
            ),
            build_latency: context.histogram(
                "build_latency",
                "application build latency",
                STAGE_LATENCY,
            ),
            validation_latency: context.histogram(
                "validation_latency",
                "application validation latency",
                WAN_LATENCY,
            ),
            vqc_bytes: context.histogram(
                "vqc_bytes",
                "encoded size of one locally assembled V-QC",
                ENCODED_BYTES,
            ),
            lqc_bytes: context.histogram(
                "lqc_bytes",
                "encoded size of one locally assembled L-QC",
                ENCODED_BYTES,
            ),
            update_bytes: context.histogram(
                "update_bytes",
                "encoded size of one published vote update",
                ENCODED_BYTES,
            ),
            service: ServiceMetrics::new(context),
            crypto_submit_wait_signing: context.histogram(
                "crypto_submit_wait_signing",
                "seconds from critical-pool submission to worker entry for local signing",
                histogram::Buckets::LOCAL,
            ),
            crypto_submit_wait_aggregation: context.histogram(
                "crypto_submit_wait_aggregation",
                "seconds from critical-pool submission to worker entry for certificate assembly",
                histogram::Buckets::LOCAL,
            ),
            verification_wait_fast: context.histogram(
                "verification_wait_fast",
                "queue wait of view-critical verification jobs before workers are reserved",
                histogram::Buckets::LOCAL,
            ),
            verification_wait_bulk: context.histogram(
                "verification_wait_bulk",
                "queue wait of bulk verification jobs before workers are reserved",
                histogram::Buckets::LOCAL,
            ),
            verification_dwell_fast: context.histogram(
                "verification_dwell_fast",
                "queueing of view-critical verification jobs through the voter applying their verdicts",
                histogram::Buckets::LOCAL,
            ),
            verification_dwell_bulk: context.histogram(
                "verification_dwell_bulk",
                "queueing of bulk verification jobs through the voter applying their verdicts",
                histogram::Buckets::LOCAL,
            ),
            verified_vote_lag: context.histogram(
                "verified_vote_lag",
                "views a valid vote update trails the current view when the voter applies its verdict",
                COUNT_POW2_FROM_ZERO,
            ),
        }
    }

    /// Counts one view proof the machine classified before verification.
    pub(crate) fn admit_view_proof(
        &self,
        source: ViewProofSource,
        kind: ViewProofKind,
        status: ObservationStatus,
    ) {
        self.view_proof_admissions
            .get_or_create(&ViewProofAdmission {
                source,
                kind,
                outcome: status.into(),
            })
            .inc();
    }

    /// Counts the adoption or view resolution one reported activity carries.
    pub(crate) fn record_activity<V: Variant, D: Digest>(&self, activity: &Activity<V, D>) {
        let counter = match activity {
            Activity::HeaderAccepted {
                adopted: Some(_), ..
            } => &self.adopted_headers,
            Activity::ViewResolved {
                by: Resolution::Determined,
                ..
            } => &self.views_determined,
            Activity::ViewResolved {
                by: Resolution::Pinned { .. },
                ..
            } => &self.views_pinned,
            _ => return,
        };
        counter.inc();
    }

    /// Adds the machine counts recorded between `earlier` and `now` to their counters.
    pub(crate) fn record_cumulative(&self, earlier: &Cumulative, now: &Cumulative) {
        for (reason, end) in ViewEndReason::ALL {
            self.view_ends
                .get_or_create(&ViewEndLabel { reason })
                .inc_by(since(earlier.ends.get(end), now.ends.get(end)));
        }
        self.view_end_millis
            .inc_by(since(earlier.ends.total_millis(), now.ends.total_millis()));
        for (label, rule) in DeclarationRuleLabel::ALL {
            let rule_label = DeclarationLabel { rule: label };
            self.declarations.get_or_create(&rule_label).inc_by(since(
                earlier.declarations.get(rule),
                now.declarations.get(rule),
            ));
            self.declaration_silence_millis
                .get_or_create(&rule_label)
                .inc_by(since(
                    earlier.contexts.silence_millis(rule),
                    now.contexts.silence_millis(rule),
                ));
            for context in DeclarationContext::ALL {
                self.declaration_contexts
                    .get_or_create(&DeclarationContextLabel::new(label, context))
                    .inc_by(since(
                        earlier.contexts.get(rule, context),
                        now.contexts.get(rule, context),
                    ));
            }
        }
        let (earlier_refusals, refusals) = (earlier.refusals, now.refusals);
        self.flow_refusals
            .inc_by(since(earlier_refusals.flow, refusals.flow));
        self.finality_refusals
            .inc_by(since(earlier_refusals.finality, refusals.finality));
        let (held, holds) = (&earlier.production_holds, &now.production_holds);
        self.production_hold_millis
            .inc_by(since(held.millis, holds.millis));
        self.production_holds
            .inc_by(since(held.holds, holds.holds));
        let (earlier, now) = (&earlier.pinned_undetermined, &now.pinned_undetermined);
        self.pinned_undetermined
            .inc_by(since(earlier.boundaries, now.boundaries));
        for (cause, earlier, now) in [
            (
                UndeterminedCause::Unresolved,
                earlier.chains.unresolved,
                now.chains.unresolved,
            ),
            (
                UndeterminedCause::Split,
                earlier.chains.split,
                now.chains.split,
            ),
        ] {
            self.undetermined_chains
                .get_or_create(&UndeterminedLabel { cause })
                .inc_by(since(earlier, now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            machine::UndeterminedChains,
            mocks::Committee,
            types::{CertificateId, ChainId, ViewProof},
        },
        types::View,
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use std::{sync::Arc, time::Duration};

    #[test]
    fn activities_count_adoptions_and_resolutions_by_kind() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(89, 6).build();
            let voter = context.child("voter");
            let metrics = Metrics::new(&voter, 6);
            let header = committee
                .genesis_child(ChainId::new(0), b"block")
                .header()
                .clone();
            let tips: Arc<[_]> = committee.genesis().tips().into();
            let resolved = |by| Activity::<MinPk, Sha256Digest>::ViewResolved {
                view: View::new(1),
                base: Arc::clone(&tips),
                tips: Arc::clone(&tips),
                commitment: Sha256::hash(&[b"commitment"]),
                parent_commitment: committee.genesis().history(),
                by,
            };
            for activity in [
                Activity::HeaderAccepted {
                    header: header.clone(),
                    adopted: None,
                },
                Activity::HeaderAccepted {
                    header,
                    adopted: Some(Duration::ZERO),
                },
                resolved(Resolution::Determined),
                resolved(Resolution::Determined),
                resolved(Resolution::Pinned {
                    view: View::new(2),
                    lqc: CertificateId::new(Sha256::hash(&[b"lqc"])),
                }),
            ] {
                metrics.record_activity(&activity);
            }
            assert_eq!(metrics.adopted_headers.get(), 1);
            assert_eq!(metrics.views_determined.get(), 2);
            assert_eq!(metrics.views_pinned.get(), 1);
        });
    }

    #[test]
    fn view_proof_kind_matches_the_projected_proof() {
        let committee = Committee::<MinPk>::builder(88, 6).build();
        let artifacts: [Artifact<MinPk, Sha256Digest>; 3] = [
            Artifact::Vqc(committee.vqc(View::new(1))),
            Artifact::Lqc(committee.lqc(View::new(1))),
            Artifact::LeaderBlock(committee.leader_block(View::new(1))),
        ];
        for artifact in &artifacts {
            let projected = ViewProof::from_artifact(artifact);
            assert_eq!(
                ViewProofKind::of(artifact),
                projected.as_ref().map(|proof| match proof {
                    ViewProof::Vqc(_) => ViewProofKind::Vqc,
                    ViewProof::Lqc(_) => ViewProofKind::Lqc,
                })
            );
        }
    }

    #[test]
    fn deployment_diagnostics_have_bounded_stable_labels() {
        deterministic::Runner::default().start(|context| async move {
            let voter = context.child("engine").child("voter");
            let metrics = Metrics::new(&voter, 1);
            metrics.artifact_cache_occupancy.set(7);
            metrics.artifact_cache_capacity.set(8);
            metrics.remote_artifact_capacity.set(5);
            metrics.local_artifact_capacity.set(7);
            metrics.verification_jobs.set(1);
            metrics.verification_job_capacity.set(2);
            metrics.future_artifacts.set(3);
            metrics.view_timer_armed.set(1);
            metrics.chain_accepted_floor.set(4);
            metrics.chain_quorum_floor.set(5);
            metrics.lagging_chains.set(0);
            metrics
                .view_proof_admissions
                .get_or_create(&ViewProofAdmission {
                    source: ViewProofSource::Resolver,
                    kind: ViewProofKind::Lqc,
                    outcome: ViewProofAdmissionOutcome::VerificationJobsFull,
                })
                .inc();

            let encoded = context.encode();
            for name in [
                "engine_voter_artifact_cache_occupancy",
                "engine_voter_artifact_cache_capacity",
                "engine_voter_remote_artifact_capacity",
                "engine_voter_local_artifact_capacity",
                "engine_voter_verification_jobs",
                "engine_voter_verification_job_capacity",
                "engine_voter_future_artifacts",
                "engine_voter_view_timer_armed",
                "engine_voter_chain_accepted_floor",
                "engine_voter_chain_quorum_floor",
                "engine_voter_lagging_chains",
                "engine_voter_adopted_headers",
                "engine_voter_views_determined",
                "engine_voter_views_pinned",
            ] {
                assert!(
                    encoded.lines().any(|line| line.starts_with(name)),
                    "missing metric {name}: {encoded}"
                );
            }
            assert_eq!(
                encoded
                    .lines()
                    .filter(|line| line.starts_with("engine_voter_view_proof_admissions_total{"))
                    .count(),
                20
            );
            assert!(encoded.lines().any(|line| {
                line.starts_with("engine_voter_view_proof_admissions_total{")
                    && line.contains("source=\"Resolver\"")
                    && line.contains("kind=\"Lqc\"")
                    && line.contains("outcome=\"VerificationJobsFull\"")
                    && line.ends_with(" 1")
            }));
            // View-end reasons and declaration rules are exported from zero, so shares and
            // rates are defined before the first view ends.
            for (prefix, series) in [
                ("engine_voter_view_ends_total{", 3),
                ("engine_voter_declarations_total{", 7),
            ] {
                assert_eq!(
                    encoded
                        .lines()
                        .filter(|line| line.starts_with(prefix) && line.ends_with(" 0"))
                        .count(),
                    series,
                    "{prefix}"
                );
            }
            for name in [
                "engine_voter_view_end_millis_total 0",
                "engine_voter_delay_estimate_milliseconds 0",
                "engine_voter_production_estimate_milliseconds 0",
                "engine_voter_grace_milliseconds 0",
            ] {
                assert!(encoded.lines().any(|line| line == name), "missing {name}");
            }
        });
    }

    #[test]
    fn cumulative_machine_counts_export_as_increments_from_zero() {
        deterministic::Runner::default().start(|context| async move {
            let voter = context.child("engine").child("voter");
            let metrics = Metrics::new(&voter, 4);
            let encoded = context.encode();
            for (prefix, series) in [
                ("engine_voter_declaration_contexts_total{", 56),
                ("engine_voter_declaration_silence_millis_total{", 7),
                ("engine_voter_undetermined_chains_total{", 2),
                ("engine_voter_artifact_transmissions_total{", 6),
                ("engine_voter_artifact_transmitted_bytes_total{", 6),
            ] {
                assert_eq!(
                    encoded
                        .lines()
                        .filter(|line| line.starts_with(prefix) && line.ends_with(" 0"))
                        .count(),
                    series,
                    "{prefix}"
                );
            }
            for name in [
                "engine_voter_flow_refusals_total 0",
                "engine_voter_finality_refusals_total 0",
                "engine_voter_pinned_undetermined_total 0",
                "engine_voter_production_hold_millis_total 0",
                "engine_voter_production_holds_total 0",
            ] {
                assert!(encoded.lines().any(|line| line == name), "missing {name}");
            }

            let progress = |flow, boundaries, split| Cumulative {
                refusals: Refusals { flow, finality: 1 },
                pinned_undetermined: PinnedUndetermined {
                    boundaries,
                    chains: UndeterminedChains {
                        unresolved: 1,
                        split,
                    },
                },
                production_holds: ProductionHolds {
                    millis: 10 * flow,
                    holds: flow,
                },
                ..Cumulative::default()
            };
            metrics.record_cumulative(&Cumulative::default(), &progress(2, 1, 3));
            metrics.record_cumulative(&progress(2, 1, 3), &progress(5, 2, 4));
            // A fresh machine restarts its counts below the exported ones: nothing is added.
            metrics.record_cumulative(&progress(5, 2, 4), &progress(1, 0, 0));
            assert_eq!(metrics.flow_refusals.get(), 5);
            assert_eq!(metrics.finality_refusals.get(), 1);
            assert_eq!(metrics.pinned_undetermined.get(), 2);
            let undetermined = |cause| {
                metrics
                    .undetermined_chains
                    .get_or_create(&UndeterminedLabel { cause })
                    .get()
            };
            assert_eq!(undetermined(UndeterminedCause::Unresolved), 1);
            assert_eq!(undetermined(UndeterminedCause::Split), 4);
            assert_eq!(metrics.production_hold_millis.get(), 50);
            assert_eq!(metrics.production_holds.get(), 5);
        });
    }

    /// Every series a node registers is scraped, shipped, and retained for every node in the
    /// deployment, so the voter's footprint at cluster scale is a deliberate budget rather than
    /// an accident. Raising this bound is a decision, not a formality.
    #[test]
    fn voter_series_footprint_stays_within_budget() {
        const CHAINS: usize = 50;
        // Includes four 213-bucket WAN histograms, two 12-bucket crypto submission histograms,
        // two 12-bucket verification dwell histograms, the 24 12-bucket service histograms that
        // split voter thread time by input kind, machine component, and lane, and the 56
        // declaration-context series.
        const BUDGET: usize = 1_750;

        deterministic::Runner::default().start(|context| async move {
            let voter = context.child("engine").child("voter");
            let _metrics = Metrics::new(&voter, CHAINS);

            let encoded = context.encode();
            for name in [
                "round_latency",
                "vqc_latency",
                "lqc_latency",
                "validation_latency",
            ] {
                let prefix = format!("engine_voter_{name}_");
                let samples: Vec<_> = encoded
                    .lines()
                    .filter(|line| line.starts_with(&prefix))
                    .collect();
                assert_eq!(samples.len(), WAN_LATENCY.len() + 3, "{name}");
                assert!(samples.iter().any(|line| line.contains("le=\"0.485\"")));
                assert!(samples.iter().all(|line| !line.contains("chain=\"")));
            }
            for name in [
                "crypto_submit_wait_signing",
                "crypto_submit_wait_aggregation",
            ] {
                let prefix = format!("engine_voter_{name}_");
                let samples: Vec<_> = encoded
                    .lines()
                    .filter(|line| line.starts_with(&prefix))
                    .collect();
                assert_eq!(samples.len(), histogram::Buckets::LOCAL.len() + 3, "{name}");
                assert!(samples.iter().all(|line| {
                    !line.contains("chain=") && !line.contains("view=") && !line.contains("job=")
                }));
            }
            let series = encoded
                .lines()
                .filter(|line| line.starts_with("engine_voter_"))
                .count();
            assert!(
                series <= BUDGET,
                "the voter registers {series} series at {CHAINS} chains, over the {BUDGET} budget"
            );
        });
    }

    /// The per-chain family scales with the validator count, so it must stay at one series
    /// per chain.
    #[test]
    fn per_chain_family_carries_only_finalized_height() {
        deterministic::Runner::default().start(|context| async move {
            let voter = context.child("engine").child("voter");
            let metrics = Metrics::new(&voter, 4);
            for chain in &metrics.chains {
                chain.finalized.set(1);
            }

            let encoded = context.encode();
            assert_eq!(
                encoded
                    .lines()
                    .filter(|line| line.starts_with("engine_voter_chains_"))
                    .count(),
                4,
                "{encoded}"
            );
        });
    }
}

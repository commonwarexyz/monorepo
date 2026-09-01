//! Metrics registered by the voter.

use crate::multimmit::{
    actors::metrics::{COUNT_POW2_FROM_ZERO, STAGE_LATENCY, Traffic, WAN_LATENCY, plane_counter},
    machine::{ObservationStatus, Rejection, SignRequest},
    types::{Anchor, Artifact, ViewProof},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::{
        metrics::{
            Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, Gauge, Histogram,
            MetricsExt as _, histogram,
        },
        traces::TracedExt as _,
    },
};
use tracing::Span;

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
    /// A nullification certificate.
    Nullification,
    /// A V-QC.
    Vqc,
    /// An L-QC.
    Lqc,
}

impl ViewProofKind {
    /// Returns the kind of view proof `artifact` carries, or `None` for other artifacts.
    pub(crate) const fn of<V: Variant, D: Digest>(artifact: &Artifact<V, D>) -> Option<Self> {
        match artifact {
            Artifact::Nullification(_) => Some(Self::Nullification),
            Artifact::Vqc(_) => Some(Self::Vqc),
            Artifact::Lqc(_) => Some(Self::Lqc),
            _ => None,
        }
    }
}

impl<V: Variant, D: Digest> From<&ViewProof<V, D>> for ViewProofKind {
    fn from(proof: &ViewProof<V, D>) -> Self {
        match proof {
            ViewProof::Nullification(_) => Self::Nullification,
            ViewProof::Vqc(_) => Self::Vqc,
            ViewProof::Lqc(_) => Self::Lqc,
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
    const KINDS: [ViewProofKind; 3] = [
        ViewProofKind::Nullification,
        ViewProofKind::Vqc,
        ViewProofKind::Lqc,
    ];
    const OUTCOMES: [ViewProofAdmissionOutcome; 5] = [
        ViewProofAdmissionOutcome::Scheduled,
        ViewProofAdmissionOutcome::Duplicate,
        ViewProofAdmissionOutcome::ArtifactCacheFull,
        ViewProofAdmissionOutcome::VerificationJobsFull,
        ViewProofAdmissionOutcome::OtherRejected,
    ];
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
    /// Durable batches awaiting journal acknowledgement; the fsync backlog.
    pub(crate) staged_batches: Gauge,
    /// Artifacts pinned by durable safety state; the retention depth behind the floors.
    pub(crate) retained_artifacts: Gauge,
    /// Nullifications above the proposal anchor; the depth of consecutive failed views.
    pub(crate) nullification_suffix: Gauge,
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
    /// Current leader-chain view. Flat means the leader chain has stopped advancing.
    pub(crate) current_view: Gauge,
    /// Retired leader-chain view floor; its distance from the current view is retention depth.
    pub(crate) retired_view: Gauge,
    /// Durable L-QC signing floor. Flat means finality has stopped.
    pub(crate) finality_floor: Gauge,
    /// Leader-chain proposal anchor view; lagging the current view means proposals are wedged.
    pub(crate) proposal_anchor_view: Gauge,
    /// Blocks this node has produced. Flat on a producer means local production has stalled.
    pub(crate) produced_blocks: Gauge,
    /// Whether the local producer is blocked at its DA pipeline limit.
    pub(crate) producer_pipeline_blocked: Gauge,
    /// Local application build slot occupancy.
    pub(crate) build_active: Gauge,
    /// Local producer bodies entering validated durable custody.
    pub(crate) custody_active: Gauge,
    /// Per-chain final heights.
    pub(crate) chains: Vec<ChainMetrics>,
    /// Lowest DA-certified height across producer chains; the certification laggard.
    pub(crate) chain_certified_floor: Gauge,
    /// Lowest locally DA-voted height across producer chains; the local DA laggard.
    pub(crate) chain_da_voted_floor: Gauge,
    /// Lowest locally known height across producer chains; the dissemination laggard.
    pub(crate) chain_known_floor: Gauge,
    /// Producer chains finalized below the highest finalized chain; the fan-out of a stall.
    pub(crate) lagging_chains: Gauge,
    /// Headers admitted while this node's sealed proposal view was current; late-arrival pressure.
    pub(crate) headers_after_seal: Gauge,
    /// Proposal-pass restarts caused by those late header admissions; wasted proposal work.
    pub(crate) header_restarts: Gauge,
    /// Leader-chain view timeouts. The primary liveness alarm.
    pub(crate) view_timeouts: Counter,
    /// Microseconds the voter thread spent inside core service cycles. Its rate is the thread's
    /// busy fraction, the saturation signal for the single-threaded machine.
    pub(crate) busy_micros: Counter,
    /// Ingress hand-off to voter ingestion of one observation cohort. The mailbox queue on the
    /// round's critical path.
    pub(crate) observation_wait: Histogram,
    /// Whether the current view timer is armed. Zero with a flat view is a halted voter.
    pub(crate) view_timer_armed: Gauge,
    /// Whether the current view timeout selected an ordinary vote.
    pub(crate) view_timeout_cutoff_vote: Gauge,
    /// Whether the current view timeout selected NoVote and Nullify.
    pub(crate) view_timeout_cutoff_timeout: Gauge,
    /// Self-certifying view proofs classified before verification; rejections are the wedge alarm.
    pub(crate) view_proof_admissions: CounterFamily<ViewProofAdmission>,
    /// Local producer deadlines reached without a build.
    pub(crate) production_stalls: Counter,
    /// Application blocks produced.
    pub(crate) builds: Counter,
    /// Application builds declined.
    pub(crate) build_declines: Counter,
    /// Application blocks rejected as invalid; a sustained rate means a misbehaving producer.
    pub(crate) invalid_blocks: Counter,
    /// Block validations the application ended without a verdict; each is scheduled again.
    pub(crate) unavailable_validations: Counter,
    /// Nullification certificates durably selected for forwarding.
    pub(crate) nullifications: Counter,
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
    /// Network observation to DA-vote signing. The data-availability arc.
    pub(crate) da_vote_latency: Histogram,
    /// CPU latency of DA certificate recovery. The dominant BLS cost at scale.
    pub(crate) da_recovery_latency: Histogram,
    /// Recoveries whose single group check failed and fell back to attributing shares.
    pub(crate) da_recovery_fallbacks: Counter,
    /// CPU latency of nullification certificate recovery.
    pub(crate) nullification_recovery_latency: Histogram,
    /// Leader-chain round latency. The consensus service objective.
    pub(crate) round_latency: Histogram,
    /// Leader-observed V-QC formation latency.
    pub(crate) vqc_latency: Histogram,
    /// Leader-observed L-QC formation latency.
    pub(crate) lqc_latency: Histogram,
    /// Application build latency; separates application cost from consensus cost.
    pub(crate) build_latency: Histogram,
    /// Application validation latency; separates application cost from consensus cost.
    pub(crate) validation_latency: Histogram,
    /// Chains one signed leader block anchors at a DA certificate rather than at the carried tip.
    pub(crate) proposal_certified_anchors: Histogram,
    /// Proposal positions endorsed by one signed vote. Coverage per unit of bandwidth.
    pub(crate) vote_positions: Histogram,
    /// Extension entries carried by one signed vote, summed over chains.
    pub(crate) vote_extensions: Histogram,
    /// Signed votes endorsing nothing; wasted bandwidth and signing capacity.
    pub(crate) empty_votes: Counter,
    /// Deviation records per aggregated certificate; drives redundant verification at scale.
    pub(crate) qc_deviations: Histogram,
    /// Encoded certificate size; the certificate-plane bandwidth driver.
    pub(crate) qc_bytes: Histogram,
    /// Queue wait of view-critical verification jobs. Rises before a straggler wedges.
    pub(crate) verification_wait_fast: Histogram,
    /// Queue wait of bulk verification jobs.
    pub(crate) verification_wait_bulk: Histogram,
    /// Critical-pool submission to worker entry for local signing, once per batch or singleton.
    pub(crate) crypto_submit_wait_signing: Histogram,
    /// Critical-pool submission to worker entry for certificate assembly and nullification recovery.
    pub(crate) crypto_submit_wait_aggregation: Histogram,
}

/// Byte-size buckets for encoded certificate histograms.
const ENCODED_BYTES: [f64; 12] = [
    64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0, 131072.0,
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
            staged_batches: context.gauge(
                "staged_batches",
                "durable batches awaiting journal acknowledgement",
            ),
            retained_artifacts: context.gauge(
                "retained_artifacts",
                "artifacts pinned by durable safety state",
            ),
            nullification_suffix: context.gauge(
                "nullification_suffix",
                "exact nullifications retained above the proposal anchor",
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
            current_view: context.gauge("current_view", "current leader-chain view"),
            retired_view: context.gauge("retired_view", "retired leader-chain view floor"),
            finality_floor: context.gauge("finality_floor", "durable L-QC signing floor"),
            proposal_anchor_view: context
                .gauge("proposal_anchor_view", "leader-chain proposal anchor view"),
            produced_blocks: context.gauge("produced_blocks", "locally produced blocks"),
            producer_pipeline_blocked: context.gauge(
                "producer_pipeline_blocked",
                "whether the local producer is blocked at its DA pipeline limit",
            ),
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
            chain_certified_floor: context.gauge(
                "chain_certified_floor",
                "lowest DA-certified height across producer chains",
            ),
            chain_da_voted_floor: context.gauge(
                "chain_da_voted_floor",
                "lowest locally DA-voted height across producer chains",
            ),
            chain_known_floor: context.gauge(
                "chain_known_floor",
                "lowest locally known height across producer chains",
            ),
            lagging_chains: context.gauge(
                "lagging_chains",
                "producer chains finalized below the highest finalized chain",
            ),
            headers_after_seal: context.gauge(
                "headers_after_seal",
                "verified headers admitted while the local sealed proposal's view was current",
            ),
            header_restarts: context.gauge(
                "header_restarts",
                "proposal-pass restarts triggered by verified header admissions",
            ),
            view_timeouts: context.counter("view_timeouts", "leader-chain view timeouts"),
            observation_wait: context.histogram(
                "observation_wait",
                "batcher hand-off to voter ingestion of one observation cohort",
                STAGE_LATENCY,
            ),
            busy_micros: context.counter(
                "busy_micros",
                "microseconds the voter thread spent inside core service cycles",
            ),
            view_timer_armed: context.gauge(
                "view_timer_armed",
                "whether the current leader-chain view timer is armed",
            ),
            view_timeout_cutoff_vote: context.gauge(
                "view_timeout_cutoff_vote",
                "whether the current view timeout selected an ordinary vote",
            ),
            view_timeout_cutoff_timeout: context.gauge(
                "view_timeout_cutoff_timeout",
                "whether the current view timeout selected NoVote and Nullify",
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
            production_stalls: context
                .counter("production_stalls", "local producer deadlines reached"),
            builds: context.counter("builds", "application blocks produced"),
            build_declines: context.counter("build_declines", "application builds declined"),
            invalid_blocks: context.counter("invalid_blocks", "application blocks rejected"),
            unavailable_validations: context.counter(
                "unavailable_validations",
                "block validations the application ended without a verdict",
            ),
            nullifications: context.counter(
                "nullifications",
                "nullification certificates durably selected for forwarding",
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
            da_vote_latency: context.histogram(
                "da_vote_latency",
                "time from first network observation of a transaction block to its DA-vote signing",
                WAN_LATENCY,
            ),
            da_recovery_latency: context.histogram(
                "da_recovery_latency",
                "CPU latency of DA certificate recovery",
                histogram::Buckets::CRYPTOGRAPHY,
            ),
            da_recovery_fallbacks: context.counter(
                "da_recovery_fallbacks",
                "DA recoveries that failed their group check and verified shares individually",
            ),
            nullification_recovery_latency: context.histogram(
                "nullification_recovery_latency",
                "CPU latency of nullification certificate recovery",
                histogram::Buckets::CRYPTOGRAPHY,
            ),
            round_latency: context.histogram(
                "round_latency",
                "leader-chain round latency",
                WAN_LATENCY,
            ),
            vqc_latency: context.histogram(
                "vqc_latency",
                "leader-observed V-QC formation latency",
                WAN_LATENCY,
            ),
            lqc_latency: context.histogram(
                "lqc_latency",
                "leader-observed L-QC formation latency",
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
            proposal_certified_anchors: context.histogram(
                "proposal_certified_anchors",
                "chains one signed leader block anchors at a DA certificate",
                COUNT_POW2_FROM_ZERO,
            ),
            vote_positions: context.histogram(
                "vote_positions",
                "proposal positions endorsed by one signed ordinary vote, summed over chains",
                COUNT_POW2_FROM_ZERO,
            ),
            empty_votes: context.counter(
                "empty_votes",
                "signed ordinary votes endorsing no positions and carrying no extensions",
            ),
            vote_extensions: context.histogram(
                "vote_extensions",
                "extension entries carried by one signed ordinary vote, summed over chains",
                COUNT_POW2_FROM_ZERO,
            ),
            qc_deviations: context.histogram(
                "qc_deviations",
                "deviation records carried by one locally aggregated quorum certificate",
                COUNT_POW2_FROM_ZERO,
            ),
            qc_bytes: context.histogram(
                "qc_bytes",
                "encoded size of one locally aggregated quorum certificate",
                ENCODED_BYTES,
            ),
            crypto_submit_wait_signing: context.histogram(
                "crypto_submit_wait_signing",
                "seconds from critical-pool submission to worker entry for local signing",
                histogram::Buckets::LOCAL,
            ),
            crypto_submit_wait_aggregation: context.histogram(
                "crypto_submit_wait_aggregation",
                "seconds from critical-pool submission to worker entry for certificate assembly and nullification recovery",
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

    /// Records the coverage of one vote or leader block about to be signed on its `span`.
    pub(crate) fn observe_sign_request<V: Variant, D: Digest>(
        &self,
        request: &SignRequest<V, D>,
        span: &Span,
    ) {
        match request {
            SignRequest::Vote(body) => {
                let positions = body
                    .positions()
                    .iter()
                    .map(|position| u64::from(position.get()))
                    .sum::<u64>();
                let extensions = body
                    .extensions()
                    .iter()
                    .map(|extension| extension.payloads().len() as u64)
                    .sum::<u64>();
                span.record("positions", positions.traced());
                span.record("extensions", extensions.traced());
                self.vote_extensions.observe(extensions as f64);
                self.vote_positions.observe(positions as f64);
                if positions == 0 && extensions == 0 {
                    self.empty_votes.inc();
                }
            }
            SignRequest::LeaderBlock(proposal) => {
                let certified = proposal
                    .block()
                    .proposals()
                    .iter()
                    .filter(|chain| matches!(chain.anchor(), Anchor::Certificate(_)))
                    .count() as u64;
                span.record("certified_anchors", certified.traced());
                self.proposal_certified_anchors.observe(certified as f64);
            }
            SignRequest::TransactionBlock(_)
            | SignRequest::DaVote(_)
            | SignRequest::NoVote { .. }
            | SignRequest::Nullify { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{mocks::Committee, types::ChainId},
        types::{Participant, View},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    #[test]
    fn view_proof_kind_matches_the_projected_proof() {
        let committee = Committee::<MinPk>::builder(88, 6).build();
        let artifacts: [Artifact<MinPk, Sha256Digest>; 6] = [
            Artifact::Nullification(committee.nullification(View::new(1))),
            Artifact::Vqc(committee.vqc(View::new(1))),
            Artifact::Lqc(committee.lqc(View::new(1))),
            Artifact::LeaderBlock(committee.leader_block(View::new(1))),
            Artifact::Nullify(committee.nullify(Participant::new(0), View::new(1))),
            Artifact::TransactionBlock(
                committee.signed_block(ChainId::new(0), Sha256::hash(&[b"body"])),
            ),
        ];
        for artifact in &artifacts {
            let projected = ViewProof::from_artifact(artifact);
            assert_eq!(
                ViewProofKind::of(artifact),
                projected.as_ref().map(ViewProofKind::from)
            );
        }
        assert_eq!(
            artifacts
                .iter()
                .filter_map(ViewProofKind::of)
                .collect::<Vec<_>>(),
            [
                ViewProofKind::Nullification,
                ViewProofKind::Vqc,
                ViewProofKind::Lqc
            ]
        );
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
            metrics.view_timeout_cutoff_timeout.set(1);
            metrics.chain_certified_floor.set(4);
            metrics.chain_da_voted_floor.set(4);
            metrics.chain_known_floor.set(5);
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
                "engine_voter_view_timeout_cutoff_vote",
                "engine_voter_view_timeout_cutoff_timeout",
                "engine_voter_chain_certified_floor",
                "engine_voter_chain_da_voted_floor",
                "engine_voter_chain_known_floor",
                "engine_voter_lagging_chains",
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
                30
            );
            assert!(encoded.lines().any(|line| {
                line.starts_with("engine_voter_view_proof_admissions_total{")
                    && line.contains("source=\"Resolver\"")
                    && line.contains("kind=\"Lqc\"")
                    && line.contains("outcome=\"VerificationJobsFull\"")
                    && line.ends_with(" 1")
            }));
        });
    }

    /// Every series a node registers is scraped, shipped, and retained for every node in the
    /// deployment, so the voter's footprint at cluster scale is a deliberate budget rather than
    /// an accident. Raising this bound is a decision, not a formality.
    #[test]
    fn voter_series_footprint_stays_within_budget() {
        const CHAINS: usize = 50;
        // Includes five 213-bucket WAN histograms and two 12-bucket crypto submission histograms.
        const BUDGET: usize = 1_538;

        deterministic::Runner::default().start(|context| async move {
            let voter = context.child("engine").child("voter");
            let _metrics = Metrics::new(&voter, CHAINS);

            let encoded = context.encode();
            for name in [
                "da_vote_latency",
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

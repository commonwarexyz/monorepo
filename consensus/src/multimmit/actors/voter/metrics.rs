use crate::{LATENCY, multimmit::actors::metrics::Traffic};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{
        Counter, CounterFamily, EncodeLabelSet, EncodeLabelValue, Gauge, Histogram,
        MetricsExt as _, histogram,
    },
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(super) enum ViewProofSource {
    Network,
    Resolver,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(super) enum ViewProofKind {
    Nullification,
    Vqc,
    Lqc,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(super) enum ViewProofAdmissionOutcome {
    Scheduled,
    Duplicate,
    ArtifactCacheFull,
    VerificationJobsFull,
    OtherRejected,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(super) struct ViewProofAdmission {
    pub source: ViewProofSource,
    pub kind: ViewProofKind,
    pub outcome: ViewProofAdmissionOutcome,
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
pub(super) struct ChainMetrics {
    /// Final height of one producer chain, so a stalled chain is attributable to its producer.
    pub finalized: Gauge,
}

impl ChainMetrics {
    fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            finalized: context.gauge("finalized", "final producer height"),
        }
    }
}

#[derive(Clone)]
pub(super) struct Metrics {
    /// Completions the machine discarded as stale; a sustained rate means wasted verification.
    pub stale: Counter,
    /// Fatal epoch failures. Any increment is an alarm.
    pub fatal: Counter,
    /// Outstanding durable publications under retry; growth means the transport is not draining.
    pub publications: Gauge,
    /// Journal events retained since the newest recovery base; sizes recovery replay work.
    pub retained_events: Gauge,
    /// Durable batches awaiting journal acknowledgement; the fsync backlog.
    pub staged_batches: Gauge,
    /// Artifacts pinned by durable safety state; the retention depth behind the floors.
    pub retained_artifacts: Gauge,
    /// Exact nullifications above the proposal anchor; the depth of consecutive failed views.
    pub nullification_suffix: Gauge,
    /// Retained artifacts plus local reservations. The numerator of cache saturation.
    pub artifact_cache_occupancy: Gauge,
    /// Configured artifact cache capacity. The denominator of cache saturation.
    pub artifact_cache_capacity: Gauge,
    /// Artifact capacity still available to untrusted ingress; zero means peers are shut out.
    pub remote_artifact_capacity: Gauge,
    /// Artifact capacity still available to local work; zero wedges local protocol progress.
    pub local_artifact_capacity: Gauge,
    /// Verification jobs in flight. The numerator of verify-pool saturation.
    pub verification_jobs: Gauge,
    /// Configured verification-job capacity. The denominator of verify-pool saturation.
    pub verification_job_capacity: Gauge,
    /// Retained future-view artifacts; a full index starves re-anchoring view proofs.
    pub future_artifacts: Gauge,
    /// Current leader-chain view. Flat means the leader chain has stopped advancing.
    pub current_view: Gauge,
    /// Retired leader-chain view floor; its distance from the current view is retention depth.
    pub retired_view: Gauge,
    /// Durable L-QC signing floor. Flat means finality has stopped.
    pub finality_floor: Gauge,
    /// Leader-chain proposal anchor view; lagging the current view means proposals are wedged.
    pub proposal_anchor_view: Gauge,
    /// Blocks this node has produced. Flat on a producer means local production has stalled.
    pub produced_blocks: Gauge,
    /// Whether the local producer is blocked at its DA pipeline limit.
    pub producer_pipeline_blocked: Gauge,
    /// Producer-block application validations executing now.
    /// Application validations waiting for execution capacity; queueing precedes view timeouts.
    /// Local application build slot occupancy.
    pub build_active_gauge: Gauge,
    /// Local producer bodies entering validated durable custody.
    pub custody_active_gauge: Gauge,
    /// Per-chain final heights.
    pub chains: Vec<ChainMetrics>,
    /// Lowest DA-certified height across producer chains; the certification laggard.
    pub chain_certified_floor: Gauge,
    /// Lowest locally DA-voted height across producer chains; the local DA laggard.
    pub chain_da_voted_floor: Gauge,
    /// Lowest locally known height across producer chains; the dissemination laggard.
    pub chain_known_floor: Gauge,
    /// Producer chains finalized below the highest finalized chain; the fan-out of a stall.
    pub lagging_chains: Gauge,
    /// Headers admitted while this node's sealed proposal view was current; late-arrival pressure.
    pub headers_after_seal: Gauge,
    /// Proposal-pass restarts caused by those late header admissions; wasted proposal work.
    pub header_restarts: Gauge,
    /// Leader-chain view timeouts. The primary liveness alarm.
    pub view_timeouts: Counter,
    /// Microseconds the voter thread spent inside core service cycles. Its rate is the thread's
    /// busy fraction, the saturation signal for the single-threaded machine.
    pub busy_micros: Counter,
    /// Batcher hand-off to voter ingestion of one observation cohort. The mailbox queue on the
    /// round's critical path.
    pub observation_wait: Histogram,
    /// Whether the current view timer is armed. Zero with a flat view is a halted voter.
    pub view_timer_armed: Gauge,
    /// Whether the current view timeout selected an ordinary vote.
    pub view_timeout_cutoff_vote: Gauge,
    /// Whether the current view timeout selected NoVote and Nullify.
    pub view_timeout_cutoff_timeout: Gauge,
    /// Self-certifying view proofs classified before verification; rejections are the wedge alarm.
    pub view_proof_admissions: CounterFamily<ViewProofAdmission>,
    /// Local producer deadlines reached without a build.
    pub production_stalls: Counter,
    /// Application blocks produced.
    pub builds: Counter,
    /// Application builds declined.
    pub build_declines: Counter,
    /// Application blocks rejected as invalid; a sustained rate means a misbehaving producer.
    pub invalid_blocks: Counter,
    /// Block validations the application ended without a verdict; each is scheduled again.
    pub unavailable_validations: Counter,
    /// Nullification certificates durably selected for forwarding.
    pub forwarded_nullifications: Counter,
    /// Transaction-block relay broadcasts requested by durable publications.
    pub relay_attempts: Counter,
    /// Relay broadcasts rejected by a closed application endpoint; any increment is a defect.
    pub relay_closed: Counter,
    /// Protocol messages accepted by the network, by plane.
    pub transmissions: CounterFamily<Traffic>,
    /// Protocol bytes accepted by the network, by plane. Egress budget.
    pub transmitted_bytes: CounterFamily<Traffic>,
    /// Protocol bytes resent by publication retries, by plane. Retry waste.
    pub retransmitted_bytes: CounterFamily<Traffic>,
    /// Network observation to DA-vote signing. The data-availability arc.
    pub da_vote_latency: Histogram,
    /// CPU latency of DA certificate recovery. The dominant BLS cost at scale.
    pub da_recovery_latency: Histogram,
    /// Recoveries whose single group check failed and fell back to attributing shares.
    pub da_recovery_fallbacks: Counter,
    /// CPU latency of nullification certificate recovery.
    pub nullification_recovery_latency: Histogram,
    /// Leader-chain round latency. The consensus service objective.
    pub round_latency: Histogram,
    /// Leader-observed V-QC formation latency.
    pub vqc_latency: Histogram,
    /// Leader-observed L-QC formation latency.
    pub lqc_latency: Histogram,
    /// Application build latency; separates application cost from consensus cost.
    pub build_latency: Histogram,
    /// Application validation latency; separates application cost from consensus cost.
    pub validation_latency: Histogram,
    /// Proposal positions endorsed by one signed vote. Coverage per unit of bandwidth.
    pub vote_positions: Histogram,
    /// Signed votes endorsing nothing; wasted bandwidth and signing capacity.
    pub empty_votes: Counter,
    /// Deviation records per aggregated certificate; drives redundant verification at scale.
    pub qc_deviations: Histogram,
    /// Encoded certificate size; the certificate-plane bandwidth driver.
    pub qc_bytes: Histogram,
    /// Queue wait of view-critical verification jobs. Rises before a straggler wedges.
    pub verification_wait_fast: Histogram,
    /// Queue wait of bulk verification jobs.
    pub verification_wait_bulk: Histogram,
}

/// Block-count buckets for per-vote coverage histograms.
///
/// The zero bucket separates votes that endorse nothing from votes with any
/// fresh coverage.
const COVERAGE: [f64; 10] = [0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0];

/// Byte-size buckets for encoded certificate histograms.
const ENCODED_BYTES: [f64; 12] = [
    64.0, 128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0, 65536.0, 131072.0,
];

impl Metrics {
    pub fn new<E: MetricsTrait>(context: &E, chain_count: usize) -> Self {
        let stale = context.counter("stale", "stale completions observed by the machine");
        let fatal = context.counter("fatal", "fatal epoch failures");
        let publications = context.gauge(
            "publications",
            "outstanding durable publications under retry",
        );
        let retained_events = context.gauge(
            "retained_events",
            "journal events retained since the newest recovery base",
        );
        let staged_batches = context.gauge(
            "staged_batches",
            "durable batches awaiting journal acknowledgement",
        );
        let retained_artifacts = context.gauge(
            "retained_artifacts",
            "artifacts pinned by durable safety state",
        );
        let nullification_suffix = context.gauge(
            "nullification_suffix",
            "exact nullifications retained above the proposal anchor",
        );
        let artifact_cache_occupancy = context.gauge(
            "artifact_cache_occupancy",
            "retained artifacts plus local protocol reservations",
        );
        let artifact_cache_capacity = context.gauge(
            "artifact_cache_capacity",
            "configured artifact cache capacity, the denominator of cache saturation",
        );
        let remote_artifact_capacity = context.gauge(
            "remote_artifact_capacity",
            "artifact capacity available to untrusted non-proof ingress",
        );
        let local_artifact_capacity = context.gauge(
            "local_artifact_capacity",
            "artifact capacity available to locally authorized non-proof work",
        );
        let verification_jobs =
            context.gauge("verification_jobs", "machine verification jobs in flight");
        let verification_job_capacity = context.gauge(
            "verification_job_capacity",
            "configured verification-job capacity, the denominator of pool saturation",
        );
        let future_artifacts = context.gauge("future_artifacts", "retained future-view artifacts");
        let current_view = context.gauge("current_view", "current leader-chain view");
        let retired_view = context.gauge("retired_view", "retired leader-chain view floor");
        let finality_floor = context.gauge("finality_floor", "durable L-QC signing floor");
        let proposal_anchor_view =
            context.gauge("proposal_anchor_view", "leader-chain proposal anchor view");
        let produced_blocks = context.gauge("produced_blocks", "locally produced blocks");
        let producer_pipeline_blocked = context.gauge(
            "producer_pipeline_blocked",
            "whether the local producer is blocked at its DA pipeline limit",
        );
        let build_active_gauge =
            context.gauge("build_active", "local application build slot occupancy");
        let custody_active_gauge = context.gauge(
            "custody_active",
            "local producer bodies entering validated durable custody",
        );
        let chains = (0..chain_count)
            .map(|chain| {
                let chain_context = context.child("chains").with_attribute("chain", chain);
                ChainMetrics::new(&chain_context)
            })
            .collect();
        let chain_certified_floor = context.gauge(
            "chain_certified_floor",
            "lowest DA-certified height across producer chains",
        );
        let chain_da_voted_floor = context.gauge(
            "chain_da_voted_floor",
            "lowest locally DA-voted height across producer chains",
        );
        let chain_known_floor = context.gauge(
            "chain_known_floor",
            "lowest locally known height across producer chains",
        );
        let lagging_chains = context.gauge(
            "lagging_chains",
            "producer chains finalized below the highest finalized chain",
        );
        let headers_after_seal = context.gauge(
            "headers_after_seal",
            "verified headers admitted while the local sealed proposal's view was current",
        );
        let header_restarts = context.gauge(
            "header_restarts",
            "proposal-pass restarts triggered by verified header admissions",
        );
        let view_timeouts = context.counter("view_timeouts", "leader-chain view timeouts");
        let observation_wait = context.histogram(
            "observation_wait",
            "batcher hand-off to voter ingestion of one observation cohort",
            LATENCY,
        );
        let busy_micros = context.counter(
            "busy_micros",
            "microseconds the voter thread spent inside core service cycles",
        );
        let view_timer_armed = context.gauge(
            "view_timer_armed",
            "whether the current leader-chain view timer is armed",
        );
        let view_timeout_cutoff_vote = context.gauge(
            "view_timeout_cutoff_vote",
            "whether the current view timeout selected an ordinary vote",
        );
        let view_timeout_cutoff_timeout = context.gauge(
            "view_timeout_cutoff_timeout",
            "whether the current view timeout selected NoVote and Nullify",
        );
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
        let production_stalls =
            context.counter("production_stalls", "local producer deadlines reached");
        let builds = context.counter("builds", "application blocks produced");
        let build_declines = context.counter("build_declines", "application builds declined");
        let invalid_blocks = context.counter("invalid_blocks", "application blocks rejected");
        let unavailable_validations = context.counter(
            "unavailable_validations",
            "block validations the application ended without a verdict",
        );
        let forwarded_nullifications = context.counter(
            "nullifications",
            "nullification certificates durably selected for forwarding",
        );
        let relay_attempts = context.counter(
            "relay_attempts",
            "transaction-block Relay broadcasts requested by durable publications",
        );
        let relay_closed = context.counter(
            "relay_closed",
            "transaction-block Relay broadcasts rejected by a closed application endpoint",
        );
        let transmissions = context.family(
            "transmissions",
            "protocol messages accepted by the network by plane and recipient",
        );
        let transmitted_bytes = context.family(
            "transmitted_bytes",
            "protocol bytes accepted by the network by plane and recipient",
        );
        let retransmitted_bytes = context.family(
            "retransmitted_bytes",
            "protocol bytes accepted by the network for publication retries, by plane",
        );
        for plane in Traffic::VOTER {
            let _ = transmissions.get_or_create(&plane);
            let _ = transmitted_bytes.get_or_create(&plane);
            let _ = retransmitted_bytes.get_or_create(&plane);
        }
        let da_vote_latency = context.histogram(
            "da_vote_latency",
            "time from first network observation of a transaction block to its DA-vote signing",
            LATENCY,
        );
        let da_recovery_latency = context.histogram(
            "da_recovery_latency",
            "CPU latency of DA certificate recovery",
            histogram::Buckets::CRYPTOGRAPHY,
        );
        let da_recovery_fallbacks = context.counter(
            "da_recovery_fallbacks",
            "DA recoveries that failed their group check and verified shares individually",
        );
        let nullification_recovery_latency = context.histogram(
            "nullification_recovery_latency",
            "CPU latency of nullification certificate recovery",
            histogram::Buckets::CRYPTOGRAPHY,
        );
        let round_latency =
            context.histogram("round_latency", "leader-chain round latency", LATENCY);
        let vqc_latency = context.histogram(
            "vqc_latency",
            "leader-observed V-QC formation latency",
            LATENCY,
        );
        let lqc_latency = context.histogram(
            "lqc_latency",
            "leader-observed L-QC formation latency",
            LATENCY,
        );
        let build_latency =
            context.histogram("build_latency", "application build latency", LATENCY);
        let validation_latency = context.histogram(
            "validation_latency",
            "application validation latency",
            LATENCY,
        );
        let vote_positions = context.histogram(
            "vote_positions",
            "proposal positions endorsed by one signed ordinary vote, summed over chains",
            COVERAGE,
        );
        let empty_votes = context.counter(
            "empty_votes",
            "signed ordinary votes endorsing no positions and carrying no extensions",
        );
        let qc_deviations = context.histogram(
            "qc_deviations",
            "deviation records carried by one locally aggregated quorum certificate",
            COVERAGE,
        );
        let qc_bytes = context.histogram(
            "qc_bytes",
            "encoded size of one locally aggregated quorum certificate",
            ENCODED_BYTES,
        );
        let verification_wait_fast = context.histogram(
            "verification_wait_fast",
            "queue wait of view-critical verification jobs before workers are reserved",
            histogram::Buckets::LOCAL,
        );
        let verification_wait_bulk = context.histogram(
            "verification_wait_bulk",
            "queue wait of bulk verification jobs before workers are reserved",
            histogram::Buckets::LOCAL,
        );

        Self {
            stale,
            fatal,
            publications,
            retained_events,
            staged_batches,
            retained_artifacts,
            nullification_suffix,
            artifact_cache_occupancy,
            artifact_cache_capacity,
            remote_artifact_capacity,
            local_artifact_capacity,
            verification_jobs,
            verification_job_capacity,
            future_artifacts,
            current_view,
            retired_view,
            finality_floor,
            proposal_anchor_view,
            produced_blocks,
            producer_pipeline_blocked,
            build_active_gauge,
            custody_active_gauge,
            chains,
            chain_certified_floor,
            chain_da_voted_floor,
            chain_known_floor,
            lagging_chains,
            headers_after_seal,
            header_restarts,
            view_timeouts,
            busy_micros,
            observation_wait,
            view_timer_armed,
            view_timeout_cutoff_vote,
            view_timeout_cutoff_timeout,
            view_proof_admissions,
            production_stalls,
            builds,
            build_declines,
            invalid_blocks,
            unavailable_validations,
            forwarded_nullifications,
            relay_attempts,
            relay_closed,
            transmissions,
            transmitted_bytes,
            retransmitted_bytes,
            da_vote_latency,
            da_recovery_latency,
            da_recovery_fallbacks,
            nullification_recovery_latency,
            round_latency,
            vqc_latency,
            lqc_latency,
            build_latency,
            validation_latency,
            vote_positions,
            empty_votes,
            qc_deviations,
            qc_bytes,
            verification_wait_fast,
            verification_wait_bulk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

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
        const BUDGET: usize = 720;

        deterministic::Runner::default().start(|context| async move {
            let voter = context.child("engine").child("voter");
            let _metrics = Metrics::new(&voter, CHAINS);

            let encoded = context.encode();
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

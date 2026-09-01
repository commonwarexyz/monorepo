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

/// Stable attribution labels for the voter loop's runtime-event sources.
pub(super) const EVENT_KINDS: [&str; 13] = [
    "persistence",
    "journal",
    "checkpoint",
    "prune",
    "application",
    "crypto",
    "timer",
    "publication",
    "heartbeat",
    "verification",
    "resolution",
    "inspection",
    "observation",
];

#[derive(Clone)]
pub(super) struct ChainMetrics {
    pub finalized: Gauge,
    pub certified: Gauge,
    pub da_voted: Gauge,
    pub known: Gauge,
}

impl ChainMetrics {
    fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            finalized: context.gauge("finalized", "final producer height"),
            certified: context.gauge("certified", "DA-certified producer height"),
            da_voted: context.gauge("da_voted", "locally DA-voted producer height"),
            known: context.gauge("known", "locally known producer height"),
        }
    }
}

#[derive(Clone)]
pub(super) struct Metrics {
    pub stale: Counter,
    pub fatal: Counter,
    pub publications: Gauge,
    pub retained_events: Gauge,
    pub staged_batches: Gauge,
    pub retained_artifacts: Gauge,
    pub artifact_cache_occupancy: Gauge,
    pub artifact_cache_capacity: Gauge,
    pub remote_artifact_capacity: Gauge,
    pub local_artifact_capacity: Gauge,
    pub verification_jobs: Gauge,
    pub verification_job_capacity: Gauge,
    pub future_artifacts: Gauge,
    pub nullification_suffix: Gauge,
    pub current_view: Gauge,
    pub retired_view: Gauge,
    pub finality_floor: Gauge,
    pub proposal_anchor_view: Gauge,
    pub produced_blocks: Gauge,
    pub producer_vote_shares: Gauge,
    pub producer_pipeline_blocked: Gauge,
    pub producer_prepared: Gauge,
    pub producer_recovery_active: Gauge,
    pub active_validations_gauge: Gauge,
    pub pending_validations_gauge: Gauge,
    pub build_active_gauge: Gauge,
    pub custody_active_gauge: Gauge,
    pub chains: Vec<ChainMetrics>,
    pub view_timeouts: Counter,
    pub view_timer_armed: Gauge,
    pub view_timeout_cutoff_vote: Gauge,
    pub view_timeout_cutoff_timeout: Gauge,
    pub view_proof_admissions: CounterFamily<ViewProofAdmission>,
    pub production_stalls: Counter,
    pub builds: Counter,
    pub build_declines: Counter,
    pub invalid_blocks: Counter,
    pub forwarded_nullifications: Counter,
    pub relay_attempts: Counter,
    pub relay_closed: Counter,
    pub transmissions: CounterFamily<Traffic>,
    pub transmitted_bytes: CounterFamily<Traffic>,
    pub retransmitted_bytes: CounterFamily<Traffic>,
    pub da_vote_latency: Histogram,
    pub da_recovery_latency: Histogram,
    pub nullification_recovery_latency: Histogram,
    pub round_latency: Histogram,
    pub vqc_latency: Histogram,
    pub lqc_latency: Histogram,
    pub build_latency: Histogram,
    pub custody_latency: Histogram,
    pub validation_latency: Histogram,
    pub ready_to_sign_latency: Histogram,
    pub sign_ready_to_wire_latency: Histogram,
    pub propose_to_sign_ready_latency: Histogram,
    pub verify_to_sign_ready_latency: Histogram,
    pub startup_drain_latency: Histogram,
    pub event_latency: Vec<Histogram>,
    pub core_cycle_latency: Histogram,
    pub vote_positions: Histogram,
    pub vote_extensions: Histogram,
    pub empty_votes: Counter,
    pub frontier_payloads: Gauge,
    pub qc_deviations: Histogram,
    pub qc_bytes: Histogram,
    pub verification_wait_fast: Histogram,
    pub verification_wait_bulk: Histogram,
    pub seal_offset_latency: Histogram,
    pub headers_after_seal: Gauge,
    pub header_restarts: Gauge,
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
        let artifact_cache_occupancy = context.gauge(
            "artifact_cache_occupancy",
            "retained artifacts plus local protocol reservations",
        );
        let artifact_cache_capacity = context.gauge(
            "artifact_cache_capacity",
            "configured artifact cache capacity",
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
            "configured machine verification-job capacity",
        );
        let future_artifacts = context.gauge("future_artifacts", "retained future-view artifacts");
        let nullification_suffix = context.gauge(
            "nullification_suffix",
            "exact nullifications retained above the proposal anchor",
        );
        let current_view = context.gauge("current_view", "current leader-chain view");
        let retired_view = context.gauge("retired_view", "retired leader-chain view floor");
        let finality_floor = context.gauge("finality_floor", "durable L-QC signing floor");
        let proposal_anchor_view =
            context.gauge("proposal_anchor_view", "leader-chain proposal anchor view");
        let produced_blocks = context.gauge("produced_blocks", "locally produced blocks");
        let producer_vote_shares = context.gauge(
            "producer_vote_shares",
            "distinct DA shares held for the local producer tip",
        );
        let producer_pipeline_blocked = context.gauge(
            "producer_pipeline_blocked",
            "whether the local producer is blocked at its DA pipeline limit",
        );
        let producer_prepared = context.gauge(
            "producer_prepared",
            "local producer blocks prepared ahead of durable signing authority",
        );
        let producer_recovery_active = context.gauge(
            "producer_recovery_active",
            "whether DA recovery is executing for the local producer tip",
        );
        let active_validations_gauge = context.gauge(
            "active_validations",
            "active producer-block application validations",
        );
        let pending_validations_gauge = context.gauge(
            "pending_validations",
            "application validations waiting for bounded execution capacity",
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
        let view_timeouts = context.counter("view_timeouts", "leader-chain view timeouts");
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
        let custody_latency = context.histogram(
            "custody_latency",
            "local producer body validation and durable-custody latency",
            LATENCY,
        );
        let validation_latency = context.histogram(
            "validation_latency",
            "application validation latency",
            LATENCY,
        );
        let ready_to_sign_latency = context.histogram(
            "ready_to_sign_latency",
            "time from private signing release to signature completion",
            LATENCY,
        );
        let sign_ready_to_wire_latency = context.histogram(
            "sign_ready_to_wire_latency",
            "time from signature completion to first transport acceptance",
            LATENCY,
        );
        let propose_to_sign_ready_latency = context.histogram(
            "propose_to_sign_ready_latency",
            "time from application proposal completion to signature completion",
            LATENCY,
        );
        let verify_to_sign_ready_latency = context.histogram(
            "verify_to_sign_ready_latency",
            "time from application verification completion to signature completion",
            LATENCY,
        );
        let startup_drain_latency = context.histogram(
            "startup_drain_latency",
            "time to drain the exact startup durability acknowledgement",
            LATENCY,
        );
        let event_latency = EVENT_KINDS
            .iter()
            .map(|kind| {
                context
                    .child("events")
                    .with_attribute("kind", kind)
                    .histogram(
                        "latency",
                        "wall-clock time servicing one runtime event",
                        histogram::Buckets::LOCAL,
                    )
            })
            .collect();
        let core_cycle_latency = context.histogram(
            "core_cycle_latency",
            "wall-clock time of one bounded core service cycle",
            histogram::Buckets::LOCAL,
        );
        let vote_positions = context.histogram(
            "vote_positions",
            "proposal positions endorsed by one signed ordinary vote, summed over chains",
            COVERAGE,
        );
        let vote_extensions = context.histogram(
            "vote_extensions",
            "extension payloads carried by one signed ordinary vote, summed over chains",
            COVERAGE,
        );
        let empty_votes = context.counter(
            "empty_votes",
            "signed ordinary votes endorsing no positions and carrying no extensions",
        );
        let frontier_payloads = context.gauge(
            "frontier_payloads",
            "cumulative own-proposal payload entries referenced before local DA endorsement",
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
        let seal_offset_latency = context.histogram(
            "seal_offset_latency",
            "time from view entry to the durable release of this leader's proposal signing",
            LATENCY,
        );
        let headers_after_seal = context.gauge(
            "headers_after_seal",
            "cumulative verified headers admitted while the local sealed proposal's view was current",
        );
        let header_restarts = context.gauge(
            "header_restarts",
            "cumulative proposal-pass restarts triggered by verified header admissions",
        );

        Self {
            stale,
            fatal,
            publications,
            retained_events,
            staged_batches,
            retained_artifacts,
            artifact_cache_occupancy,
            artifact_cache_capacity,
            remote_artifact_capacity,
            local_artifact_capacity,
            verification_jobs,
            verification_job_capacity,
            future_artifacts,
            nullification_suffix,
            current_view,
            retired_view,
            finality_floor,
            proposal_anchor_view,
            produced_blocks,
            producer_vote_shares,
            producer_pipeline_blocked,
            producer_prepared,
            producer_recovery_active,
            active_validations_gauge,
            pending_validations_gauge,
            build_active_gauge,
            custody_active_gauge,
            chains,
            view_timeouts,
            view_timer_armed,
            view_timeout_cutoff_vote,
            view_timeout_cutoff_timeout,
            view_proof_admissions,
            production_stalls,
            builds,
            build_declines,
            invalid_blocks,
            forwarded_nullifications,
            relay_attempts,
            relay_closed,
            transmissions,
            transmitted_bytes,
            retransmitted_bytes,
            da_vote_latency,
            da_recovery_latency,
            nullification_recovery_latency,
            round_latency,
            vqc_latency,
            lqc_latency,
            build_latency,
            custody_latency,
            validation_latency,
            ready_to_sign_latency,
            sign_ready_to_wire_latency,
            propose_to_sign_ready_latency,
            verify_to_sign_ready_latency,
            startup_drain_latency,
            event_latency,
            core_cycle_latency,
            vote_positions,
            vote_extensions,
            empty_votes,
            frontier_payloads,
            qc_deviations,
            qc_bytes,
            verification_wait_fast,
            verification_wait_bulk,
            seal_offset_latency,
            headers_after_seal,
            header_restarts,
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
}

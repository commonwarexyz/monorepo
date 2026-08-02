use crate::{LATENCY, multimmit::actors::metrics::Traffic};
use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Counter, CounterFamily, Gauge, Histogram, MetricsExt as _, histogram},
};

#[derive(Clone)]
pub(super) struct ChainMetrics {
    pub finalized: Gauge,
    pub certified: Gauge,
    pub known: Gauge,
}

impl ChainMetrics {
    fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            finalized: context.gauge("finalized", "final producer height"),
            certified: context.gauge("certified", "DA-certified producer height"),
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
    pub production_stalls: Counter,
    pub builds: Counter,
    pub build_declines: Counter,
    pub invalid_blocks: Counter,
    pub forwarded_nullifications: Counter,
    pub relay_attempts: Counter,
    pub relay_closed: Counter,
    pub transmissions: CounterFamily<Traffic>,
    pub transmitted_bytes: CounterFamily<Traffic>,
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
}

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
        for plane in Traffic::VOTER {
            let _ = transmissions.get_or_create(&plane);
            let _ = transmitted_bytes.get_or_create(&plane);
        }
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

        Self {
            stale,
            fatal,
            publications,
            retained_events,
            staged_batches,
            retained_artifacts,
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
            production_stalls,
            builds,
            build_declines,
            invalid_blocks,
            forwarded_nullifications,
            relay_attempts,
            relay_closed,
            transmissions,
            transmitted_bytes,
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
        }
    }
}

//! Marshal metrics.

use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};

/// Marshal's metrics.
pub(crate) struct Metrics {
    /// The highest output index durable proofs authenticate that marshal took into its order.
    pub(crate) proven: Gauge,
    /// The highest output index delivered to the application.
    pub(crate) delivered: Gauge,
    /// The highest output index durably acknowledged.
    pub(crate) acknowledged: Gauge,
    /// History records stored.
    pub(crate) records: Counter,
    /// L-QCs stored.
    pub(crate) lqcs: Counter,
    /// Block fetches issued to peers.
    pub(crate) fetches: Counter,
    /// Blocks received from peers.
    pub(crate) fetched_blocks: Counter,
    /// Blocks found in the broadcast buffer instead of fetched.
    pub(crate) buffered_blocks: Counter,
    /// Peer responses rejected.
    pub(crate) invalid_responses: Counter,
    /// Peer requests answered.
    pub(crate) served: Counter,
    /// Record walks started to connect a proof to the delivered history.
    pub(crate) walks: Counter,
    /// Whether peers report pruning the history marshal needs: a floor install is needed.
    pub(crate) beyond_retention: Gauge,
    /// Bytes of block bodies held in memory ahead of delivery.
    pub(crate) hot_bytes: Gauge,
    /// Durability cuts of the custody stream.
    pub(crate) custody_cuts: Counter,
    /// Floors installed.
    pub(crate) floors: Counter,
    /// Prunes applied.
    pub(crate) prunes: Counter,
    /// Turns of the owner: each takes a batch of ready inputs and drives the machines once.
    pub(crate) turns: Counter,
    /// Inputs the owner took.
    pub(crate) inputs: Counter,
}

impl Metrics {
    /// Registers the metrics under `context`.
    pub(crate) fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            proven: context.gauge(
                "proven",
                "Highest output index taken into the order from durable proofs",
            ),
            delivered: context.gauge(
                "delivered",
                "Highest output index delivered to the application",
            ),
            acknowledged: context
                .gauge("acknowledged", "Highest output index durably acknowledged"),
            records: context.counter("records", "History records stored"),
            lqcs: context.counter("lqcs", "L-QCs stored"),
            fetches: context.counter("fetches", "Block fetches issued to peers"),
            fetched_blocks: context.counter("fetched_blocks", "Blocks received from peers"),
            buffered_blocks: context
                .counter("buffered_blocks", "Blocks found in the broadcast buffer"),
            invalid_responses: context.counter("invalid_responses", "Peer responses rejected"),
            served: context.counter("served", "Peer requests answered"),
            walks: context.counter("walks", "Record walks started"),
            beyond_retention: context.gauge(
                "beyond_retention",
                "Whether peers pruned the history marshal needs",
            ),
            hot_bytes: context.gauge("hot_bytes", "Bytes of block bodies held ahead of delivery"),
            custody_cuts: context.counter("custody_cuts", "Durability cuts of the custody stream"),
            floors: context.counter("floors", "Floors installed"),
            prunes: context.counter("prunes", "Prunes applied"),
            turns: context.counter("turns", "Turns of the owner, each driving the machines once"),
            inputs: context.counter("inputs", "Inputs the owner took"),
        }
    }
}

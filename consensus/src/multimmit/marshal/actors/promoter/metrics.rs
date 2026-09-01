//! Promoter metrics.

use crate::multimmit::marshal::{actors::metrics::saturating_u64, types::OutputIndex};
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
};

/// Immutable promotion progress.
pub(super) struct Metrics {
    batches: Counter,
    outputs: Counter,
    bytes: Counter,
    hot_bodies: Counter,
    fallback_bodies: Counter,
    promoted_count: Gauge,
}

impl Metrics {
    pub(super) fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            batches: context.counter(
                "batches_total",
                "Immutable finalized-body batches made durable",
            ),
            outputs: context.counter(
                "outputs_total",
                "Finalized block bodies made durable in immutable storage",
            ),
            bytes: context.counter(
                "bytes_total",
                "Encoded finalized block bytes made durable in immutable storage",
            ),
            hot_bodies: context.counter(
                "hot_bodies_total",
                "Immutable promotions satisfied by post-commit memory",
            ),
            fallback_bodies: context.counter(
                "fallback_bodies_total",
                "Immutable promotions not satisfied by the post-commit handoff",
            ),
            promoted_count: context.gauge(
                "promoted_output_count",
                "Number of dense outputs through the immutable promotion cursor",
            ),
        }
    }

    /// Publishes the durable promotion cursor.
    pub(super) fn progress(&self, through: Option<OutputIndex>) {
        let _ = self.promoted_count.try_set(OutputIndex::count(through));
    }

    /// Counts one promoted batch of `outputs` outputs, `hot` of them from handed-off bodies.
    pub(super) fn batch(&self, outputs: usize, bytes: u64, hot: usize) {
        self.batches.inc();
        self.outputs.inc_by(saturating_u64(outputs));
        self.bytes.inc_by(bytes);
        self.hot_bodies.inc_by(saturating_u64(hot));
        self.fallback_bodies
            .inc_by(saturating_u64(outputs.saturating_sub(hot)));
    }
}

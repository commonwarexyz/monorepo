//! Delivery metrics.

use crate::multimmit::marshal::{actors::metrics::saturating_u64, types::OutputIndex};
use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _, histogram},
};

/// Application delivery progress and pressure.
pub(super) struct Metrics {
    attempts: Counter,
    hot_outputs: Counter,
    stored_outputs: Counter,
    acknowledgements: Counter,
    acknowledgement_starts: Counter,
    acknowledgement_durability: histogram::Timed,
    acknowledgement_completion: histogram::Timed,
    acknowledged_count: Gauge,
    in_flight: Gauge,
    pending_durability: Gauge,
}

impl Metrics {
    pub(super) fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            attempts: context.counter(
                "attempts_total",
                "Application delivery attempts, including crash redeliveries",
            ),
            hot_outputs: context.counter(
                "hot_outputs",
                "Outputs delivered from post-commit memory without a storage read",
            ),
            stored_outputs: context.counter(
                "stored_outputs",
                "Outputs materialized from storage for application delivery",
            ),
            acknowledgements: context.counter(
                "acknowledgements_total",
                "Application acknowledgements durably committed",
            ),
            acknowledgement_starts: context.counter(
                "acknowledgement_starts_total",
                "Application acknowledgement prefixes accepted for durable publication",
            ),
            acknowledgement_durability: histogram::Timed::register(
                context,
                "acknowledgement_durability_duration",
                "Duration of one application acknowledgement metadata sync",
            ),
            acknowledgement_completion: histogram::Timed::new(context.histogram(
                "acknowledgement_completion_duration",
                "Duration from the first application acknowledgement in a coalesced prefix through durable cursor publication",
                histogram::Buckets::NETWORK,
            )),
            acknowledged_count: context.gauge(
                "acknowledged_output_count",
                "Number of dense outputs through the durable acknowledgement cursor",
            ),
            in_flight: context.gauge(
                "in_flight",
                "Application updates awaiting an Exact acknowledgement",
            ),
            pending_durability: context.gauge(
                "pending_durability",
                "Application-acknowledged outputs awaiting durable cursor publication",
            ),
        }
    }

    /// Counts one output reported to the application.
    pub(super) fn attempted(&self) {
        self.attempts.inc();
    }

    /// Counts one output reported from a hot body.
    pub(super) fn hot_output(&self) {
        self.hot_outputs.inc();
    }

    /// Counts outputs reported from bodies read back from storage.
    pub(super) fn stored_outputs(&self, outputs: usize) {
        self.stored_outputs.inc_by(saturating_u64(outputs));
    }

    /// Counts one acknowledged prefix whose cursor sync started.
    pub(super) fn acknowledgement_started(&self) {
        self.acknowledgement_starts.inc();
    }

    /// Counts outputs whose acknowledgements became durable.
    pub(super) fn acknowledged(&self, outputs: usize) {
        self.acknowledgements.inc_by(saturating_u64(outputs));
    }

    /// Starts timing one cursor sync.
    pub(super) fn durability_timer(&self, clock: &impl Clock) -> histogram::Timer {
        self.acknowledgement_durability.timer(clock)
    }

    /// Starts timing one acknowledged prefix through its durable cursor.
    pub(super) fn completion_timer(&self, clock: &impl Clock) -> histogram::Timer {
        self.acknowledgement_completion.timer(clock)
    }

    /// Publishes reported outputs awaiting acknowledgement.
    pub(super) fn in_flight(&self, count: usize) {
        let _ = self.in_flight.try_set(count);
    }

    /// Publishes acknowledged outputs awaiting a durable cursor.
    pub(super) fn pending_durability(&self, count: usize) {
        let _ = self.pending_durability.try_set(count);
    }

    /// Publishes the durable acknowledgement cursor.
    pub(super) fn progress(&self, through: Option<OutputIndex>) {
        let _ = self.acknowledged_count.try_set(OutputIndex::count(through));
    }
}

use std::sync::Arc;

use commonware_runtime::{
    telemetry::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use commonware_utils::Array;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
};

/// Label for sequencer height metrics
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SequencerLabel {
    /// Hex representation of the sequencer's public key
    pub sequencer: String,
}

impl SequencerLabel {
    /// Create a new sequencer label from a public key
    pub fn from<A: Array>(sequencer: &A) -> Self {
        Self {
            sequencer: sequencer.to_string(),
        }
    }
}

/// Metrics for the broadcast/linked module.
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Height per sequencer
    pub sequencer_heights: Family<SequencerLabel, Gauge>,
    /// Number of acks processed by status
    pub acks: status::Counter,
    /// Number of nodes processed by status
    pub nodes: status::Counter,
    /// Number of application verifications by status
    pub verify: status::Counter,
    /// Number of threshold signatures produced
    pub threshold: Counter,
    /// Number of new broadcast attempts by status
    pub new_broadcast: status::Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
    /// Histogram of application verification durations
    pub verify_duration: histogram::Timed<E>,
    /// Histogram of time from new broadcast to threshold signature generation
    pub e2e_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let clock = Arc::new(context.clone());
        let verify_duration = Histogram::new(histogram::Buckets::LOCAL.into_iter());
        let e2e_duration = Histogram::new(histogram::Buckets::NETWORK.into_iter());

        let metrics = Self {
            sequencer_heights: Family::default(),
            acks: status::Counter::default(),
            nodes: status::Counter::default(),
            verify: status::Counter::default(),
            threshold: Counter::default(),
            new_broadcast: status::Counter::default(),
            rebroadcast: status::Counter::default(),
            verify_duration: histogram::Timed::new(verify_duration.clone(), Arc::clone(&clock)),
            e2e_duration: histogram::Timed::new(e2e_duration.clone(), Arc::clone(&clock)),
        };
        context.register(
            "sequencer_heights",
            "Height per sequencer tracked",
            metrics.sequencer_heights.clone(),
        );
        context.register(
            "acks",
            "Number of acks processed by status",
            metrics.acks.clone(),
        );
        context.register(
            "nodes",
            "Number of nodes processed by status",
            metrics.nodes.clone(),
        );
        context.register(
            "verify",
            "Number of application verifications by status",
            metrics.verify.clone(),
        );
        context.register(
            "threshold",
            "Number of threshold signatures produced",
            metrics.threshold.clone(),
        );
        context.register(
            "new_broadcast",
            "Number of new broadcast attempts by status",
            metrics.new_broadcast.clone(),
        );
        context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            metrics.rebroadcast.clone(),
        );
        context.register(
            "verify_duration",
            "Histogram of application verification durations",
            verify_duration,
        );
        context.register(
            "e2e_duration",
            "Histogram of time from broadcast to threshold signature generation",
            e2e_duration,
        );
        metrics
    }
}

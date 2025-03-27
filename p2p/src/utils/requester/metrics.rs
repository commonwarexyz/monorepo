//! Metrics for the requester.

use commonware_runtime::telemetry::metrics::histogram::Buckets;
use commonware_utils::Array;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
};

/// Label for peer metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PeerLabel {
    /// Hex representation of the peer's public key
    pub peer: String,
}

impl PeerLabel {
    /// Create a new peer label from a public key
    pub fn from<A: Array>(peer: &A) -> Self {
        Self {
            peer: peer.to_string(),
        }
    }
}

/// Metrics for the requester.
#[derive(Debug)]
pub struct Metrics {
    /// Number of requests made.
    pub requests: Counter,
    /// Number of requests that timed out.
    pub timeouts: Counter,
    /// Number and duration of requests that were resolved.
    pub resolves: Histogram,
    /// Performance of each peer
    pub performance: Family<PeerLabel, Gauge>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given registry.
    pub fn init<M: commonware_runtime::Metrics>(registry: M) -> Self {
        let metrics = Self {
            requests: Counter::default(),
            timeouts: Counter::default(),
            resolves: Histogram::new(Buckets::NETWORK.into_iter()),
            performance: Family::default(),
        };
        registry.register(
            "requests",
            "Number of requests made",
            metrics.requests.clone(),
        );
        registry.register(
            "timeouts",
            "Number of requests that timed out",
            metrics.timeouts.clone(),
        );
        registry.register(
            "resolves",
            "Number and duration of requests that were resolved",
            metrics.resolves.clone(),
        );
        registry.register(
            "performance",
            "Performance of each peer",
            metrics.performance.clone(),
        );
        metrics
    }
}

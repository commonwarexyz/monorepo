//! Metrics for the requester.

use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::{histogram::Buckets, status};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge, histogram::Histogram},
};

/// Label for peer metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PeerLabel {
    /// Hex representation of the peer's public key
    pub peer: String,
}

impl PeerLabel {
    /// Create a new peer label from a public key
    pub fn from<P: PublicKey>(peer: &P) -> Self {
        Self {
            peer: peer.to_string(),
        }
    }
}

/// Metrics for the requester.
#[derive(Debug)]
pub struct Metrics {
    /// Status of all request creation attempts.
    pub created: status::Counter,
    /// Status of all requests that were successfully created.
    pub requests: status::Counter,
    /// Number and duration of requests that were successfully resolved.
    pub resolves: Histogram,
    /// Performance of each peer
    pub performance: Family<PeerLabel, Gauge>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given registry.
    pub fn init<M: commonware_runtime::Metrics>(registry: M) -> Self {
        let metrics = Self {
            created: status::Counter::default(),
            requests: status::Counter::default(),
            resolves: Histogram::new(Buckets::NETWORK.into_iter()),
            performance: Family::default(),
        };
        registry.register(
            "created",
            "Status of all request creation attempts",
            metrics.created.clone(),
        );
        registry.register(
            "requests",
            "Status of all requests that were successfully created",
            metrics.requests.clone(),
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

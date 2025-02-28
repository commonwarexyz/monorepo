use commonware_runtime::metrics::{histogram::Buckets, status};
use prometheus_client::metrics::{gauge::Gauge, histogram::Histogram};

/// Metrics for the peer actor.
#[derive(Debug)]
pub struct Metrics {
    /// Current number of pending fetch requests
    pub fetch_pending: Gauge,
    /// Current number of active fetch requests
    pub fetch_active: Gauge,
    /// Current number of serves currently in flight
    pub serve_processing: Gauge,
    /// Current number of blocked peers
    pub peers_blocked: Gauge,
    /// Number of fetches by status
    pub fetch: status::Counter,
    /// Number of canceled fetches by status
    pub cancel: status::Counter,
    /// Number of serves by status
    pub serve: status::Counter,
    /// Histogram of successful serves
    pub serve_duration: Histogram,
    /// Histogram of successful fetches
    pub fetch_duration: Histogram,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given registry.
    pub fn init<M: commonware_runtime::Metrics>(registry: M) -> Self {
        let metrics = Self {
            fetch_pending: Gauge::default(),
            fetch_active: Gauge::default(),
            serve_processing: Gauge::default(),
            peers_blocked: Gauge::default(),
            fetch: status::Counter::default(),
            cancel: status::Counter::default(),
            serve: status::Counter::default(),
            serve_duration: Histogram::new(Buckets::LOCAL.into_iter()),
            fetch_duration: Histogram::new(Buckets::NETWORK.into_iter()),
        };
        registry.register(
            "fetch_pending",
            "Current number of pending fetch requests",
            metrics.fetch_pending.clone(),
        );
        registry.register(
            "fetch_active",
            "Current number of active fetch requests",
            metrics.fetch_active.clone(),
        );
        registry.register(
            "serve_processing",
            "Current number of serves currently processing",
            metrics.serve_processing.clone(),
        );
        registry.register(
            "peers_blocked",
            "Current number of blocked peers",
            metrics.peers_blocked.clone(),
        );
        registry.register(
            "fetch",
            "Number of fetches by status",
            metrics.fetch.clone(),
        );
        registry.register(
            "cancel",
            "Number of canceled fetches by status",
            metrics.cancel.clone(),
        );
        registry.register("serve", "Number of serves by status", metrics.serve.clone());
        registry.register(
            "serve_duration",
            "Histogram of successful serves",
            metrics.serve_duration.clone(),
        );
        registry.register(
            "fetch_duration",
            "Histogram of successful fetches",
            metrics.fetch_duration.clone(),
        );
        metrics
    }
}

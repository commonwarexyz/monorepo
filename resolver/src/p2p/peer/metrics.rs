use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Metrics for the peer actor.
#[derive(Default, Debug)]
pub struct Metrics {
    /// Number of pending fetch requests
    pub fetch_pending: Gauge,
    /// Number of active fetch requests
    pub fetch_active: Gauge,
    /// Number of serving operations currently in flight
    pub serve_in_flight: Gauge,
    /// Total number of successful fetches
    pub fetch_success: Counter,
    /// Total number of failed fetches
    pub fetch_failure: Counter,
    /// Total number of successful serves
    pub serve_success: Counter,
    /// Total number of failed serves
    pub serve_failure: Counter,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given registry.
    pub fn init<M: commonware_runtime::Metrics>(registry: M) -> Self {
        let metrics = Self::default();
        registry.register(
            "fetch_pending",
            "Number of pending fetch requests",
            metrics.fetch_pending.clone(),
        );
        registry.register(
            "fetch_active",
            "Number of active fetch requests",
            metrics.fetch_active.clone(),
        );
        registry.register(
            "serve_in_flight",
            "Number of serving operations currently in flight",
            metrics.serve_in_flight.clone(),
        );
        registry.register(
            "fetch_success",
            "Total number of successful fetches",
            metrics.fetch_success.clone(),
        );
        registry.register(
            "fetch_failure",
            "Total number of failed fetches",
            metrics.fetch_failure.clone(),
        );
        registry.register(
            "serve_success",
            "Total number of successful serves",
            metrics.serve_success.clone(),
        );
        registry.register(
            "serve_failure",
            "Total number of failed serves",
            metrics.serve_failure.clone(),
        );
        metrics
    }
}

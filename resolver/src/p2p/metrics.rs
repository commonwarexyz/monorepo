use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Metrics as RuntimeMetrics,
};
use prometheus_client::metrics::{gauge::Gauge, histogram::Histogram};

/// Metrics for the peer actor.
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
    pub serve_duration: histogram::Timed,
    /// Histogram of successful fetches
    pub fetch_duration: histogram::Timed,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let serve_duration = context.register(
            "serve_duration",
            "Histogram of successful serves",
            Histogram::new(histogram::Buckets::LOCAL),
        );
        let fetch_duration = context.register(
            "fetch_duration",
            "Histogram of successful fetches",
            Histogram::new(histogram::Buckets::NETWORK),
        );
        Self {
            fetch_pending: context.register(
                "fetch_pending",
                "Current number of pending fetch requests",
                Gauge::default(),
            ),
            fetch_active: context.register(
                "fetch_active",
                "Current number of active fetch requests",
                Gauge::default(),
            ),
            serve_processing: context.register(
                "serve_processing",
                "Current number of serves currently processing",
                Gauge::default(),
            ),
            peers_blocked: context.register(
                "peers_blocked",
                "Current number of blocked peers",
                Gauge::default(),
            ),
            fetch: context.register(
                "fetch",
                "Number of fetches by status",
                status::Counter::default(),
            ),
            cancel: context.register(
                "cancel",
                "Number of canceled fetches by status",
                status::Counter::default(),
            ),
            serve: context.register(
                "serve",
                "Number of serves by status",
                status::Counter::default(),
            ),
            fetch_duration: histogram::Timed::new(fetch_duration),
            serve_duration: histogram::Timed::new(serve_duration),
        }
    }
}

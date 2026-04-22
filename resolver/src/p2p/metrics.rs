use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics, Registered,
};
use prometheus_client::metrics::{gauge::Gauge, histogram::Histogram};
use std::sync::Arc;

/// Metrics for the peer actor.
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Current number of pending fetch requests
    pub fetch_pending: Registered<Gauge>,
    /// Current number of active fetch requests
    pub fetch_active: Registered<Gauge>,
    /// Current number of serves currently in flight
    pub serve_processing: Registered<Gauge>,
    /// Current number of blocked peers
    pub peers_blocked: Registered<Gauge>,
    /// Number of fetches by status
    pub fetch: Registered<status::Counter>,
    /// Number of canceled fetches by status
    pub cancel: Registered<status::Counter>,
    /// Number of serves by status
    pub serve: Registered<status::Counter>,
    /// Histogram of successful serves
    pub serve_duration: histogram::Timed<E, Registered<Histogram>>,
    /// Histogram of successful fetches
    pub fetch_duration: histogram::Timed<E, Registered<Histogram>>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let fetch_pending = context.register(
            "fetch_pending",
            "Current number of pending fetch requests",
            Gauge::default(),
        );
        let fetch_active = context.register(
            "fetch_active",
            "Current number of active fetch requests",
            Gauge::default(),
        );
        let serve_processing = context.register(
            "serve_processing",
            "Current number of serves currently processing",
            Gauge::default(),
        );
        let peers_blocked = context.register(
            "peers_blocked",
            "Current number of blocked peers",
            Gauge::default(),
        );
        let fetch = context.register(
            "fetch",
            "Number of fetches by status",
            status::Counter::default(),
        );
        let cancel = context.register(
            "cancel",
            "Number of canceled fetches by status",
            status::Counter::default(),
        );
        let serve = context.register(
            "serve",
            "Number of serves by status",
            status::Counter::default(),
        );
        let serve_duration_registered = context.register(
            "serve_duration",
            "Histogram of successful serves",
            Histogram::new(histogram::Buckets::LOCAL),
        );
        let fetch_duration_registered = context.register(
            "fetch_duration",
            "Histogram of successful fetches",
            Histogram::new(histogram::Buckets::NETWORK),
        );
        let clock = Arc::new(context);

        Self {
            fetch_pending,
            fetch_active,
            serve_processing,
            peers_blocked,
            fetch,
            cancel,
            serve,
            fetch_duration: histogram::Timed::new(fetch_duration_registered, clock.clone()),
            serve_duration: histogram::Timed::new(serve_duration_registered, clock),
        }
    }
}

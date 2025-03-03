use commonware_runtime::{
    telemetry::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use prometheus_client::metrics::{gauge::Gauge, histogram::Histogram};
use std::sync::Arc;

/// Metrics for the peer actor.
pub struct Metrics<E: RuntimeMetrics + Clock> {
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
    pub serve_duration: histogram::Timed<E>,
    /// Histogram of successful fetches
    pub fetch_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let clock = Arc::new(context.clone());
        let serve_duration = Histogram::new(histogram::Buckets::LOCAL.into_iter());
        let fetch_duration = Histogram::new(histogram::Buckets::NETWORK.into_iter());
        let metrics = Self {
            fetch_pending: Gauge::default(),
            fetch_active: Gauge::default(),
            serve_processing: Gauge::default(),
            peers_blocked: Gauge::default(),
            fetch: status::Counter::default(),
            cancel: status::Counter::default(),
            serve: status::Counter::default(),
            fetch_duration: histogram::Timed::new(fetch_duration.clone(), clock.clone()),
            serve_duration: histogram::Timed::new(serve_duration.clone(), clock.clone()),
        };
        context.register(
            "fetch_pending",
            "Current number of pending fetch requests",
            metrics.fetch_pending.clone(),
        );
        context.register(
            "fetch_active",
            "Current number of active fetch requests",
            metrics.fetch_active.clone(),
        );
        context.register(
            "serve_processing",
            "Current number of serves currently processing",
            metrics.serve_processing.clone(),
        );
        context.register(
            "peers_blocked",
            "Current number of blocked peers",
            metrics.peers_blocked.clone(),
        );
        context.register(
            "fetch",
            "Number of fetches by status",
            metrics.fetch.clone(),
        );
        context.register(
            "cancel",
            "Number of canceled fetches by status",
            metrics.cancel.clone(),
        );
        context.register("serve", "Number of serves by status", metrics.serve.clone());
        context.register(
            "serve_duration",
            "Histogram of successful serves",
            serve_duration,
        );
        context.register(
            "fetch_duration",
            "Histogram of successful fetches",
            fetch_duration,
        );
        metrics
    }
}

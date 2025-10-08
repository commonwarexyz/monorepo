use commonware_runtime::{
    telemetry::metrics::{histogram, status},
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
        let fetch_pending = Gauge::default();
        context.register(
            "fetch_pending",
            "Current number of pending fetch requests",
            fetch_pending.clone(),
        );
        let fetch_active = Gauge::default();
        context.register(
            "fetch_active",
            "Current number of active fetch requests",
            fetch_active.clone(),
        );
        let serve_processing = Gauge::default();
        context.register(
            "serve_processing",
            "Current number of serves currently processing",
            serve_processing.clone(),
        );
        let peers_blocked = Gauge::default();
        context.register(
            "peers_blocked",
            "Current number of blocked peers",
            peers_blocked.clone(),
        );
        let fetch = status::Counter::default();
        context.register("fetch", "Number of fetches by status", fetch.clone());
        let cancel = status::Counter::default();
        context.register(
            "cancel",
            "Number of canceled fetches by status",
            cancel.clone(),
        );
        let serve = status::Counter::default();
        context.register("serve", "Number of serves by status", serve.clone());
        let serve_duration = Histogram::new(histogram::Buckets::LOCAL.into_iter());
        context.register(
            "serve_duration",
            "Histogram of successful serves",
            serve_duration.clone(),
        );
        let fetch_duration = Histogram::new(histogram::Buckets::NETWORK.into_iter());
        context.register(
            "fetch_duration",
            "Histogram of successful fetches",
            fetch_duration.clone(),
        );
        // TODO(#1833): Shouldn't require another clone
        let clock = Arc::new(context.clone());

        Self {
            fetch_pending,
            fetch_active,
            serve_processing,
            peers_blocked,
            fetch,
            cancel,
            serve,
            fetch_duration: histogram::Timed::new(fetch_duration, clock.clone()),
            serve_duration: histogram::Timed::new(serve_duration, clock),
        }
    }
}

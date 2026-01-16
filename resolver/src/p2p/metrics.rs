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
        let fetch_pending = context.get_or_register_default::<Gauge>(
            "fetch_pending",
            "Current number of pending fetch requests",
        );
        let fetch_active = context.get_or_register_default::<Gauge>(
            "fetch_active",
            "Current number of active fetch requests",
        );
        let serve_processing = context.get_or_register_default::<Gauge>(
            "serve_processing",
            "Current number of serves currently processing",
        );
        let peers_blocked = context
            .get_or_register_default::<Gauge>("peers_blocked", "Current number of blocked peers");
        let fetch = context
            .get_or_register_default::<status::Counter>("fetch", "Number of fetches by status");
        let cancel = context.get_or_register_default::<status::Counter>(
            "cancel",
            "Number of canceled fetches by status",
        );
        let serve = context
            .get_or_register_default::<status::Counter>("serve", "Number of serves by status");
        let serve_duration = context.get_or_register_with(
            "serve_duration",
            "Histogram of successful serves",
            || Histogram::new(histogram::Buckets::LOCAL),
        );
        let fetch_duration = context.get_or_register_with(
            "fetch_duration",
            "Histogram of successful fetches",
            || Histogram::new(histogram::Buckets::NETWORK),
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
            fetch_duration: histogram::Timed::new(fetch_duration, clock.clone()),
            serve_duration: histogram::Timed::new(serve_duration, clock),
        }
    }
}

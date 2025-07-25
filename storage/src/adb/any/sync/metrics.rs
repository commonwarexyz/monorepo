use std::sync::Arc;

use commonware_runtime::{
    telemetry::metrics::histogram::{Buckets, Timed},
    Clock,
};
use prometheus_client::metrics::{counter::Counter, histogram::Histogram};

/// Prometheus metrics for the sync client.
pub(super) struct Metrics<E: Clock> {
    /// Number of valid batches successfully received and processed.
    pub(super) valid_batches_received: Counter<u64>,
    /// Number of invalid batches received that failed validation.
    pub(super) invalid_batches_received: Counter<u64>,
    /// Total number of operations fetched during sync.
    pub(super) operations_fetched: Counter<u64>,
    /// Total time spent fetching operations from resolver (seconds).
    pub(super) _fetch_duration: Timed<E>,
    /// Total time spent verifying proofs (seconds).
    pub(super) proof_verification_duration: Timed<E>,
    /// Total time spent applying operations to the log (seconds).
    pub(super) apply_duration: Timed<E>,
}

impl<E: Clock + commonware_runtime::Metrics> Metrics<E> {
    /// Register metrics with the provided runtime metrics context and return the struct.
    pub fn new(context: E) -> Self {
        let fetch_histogram = Histogram::new(Buckets::NETWORK.into_iter());
        let proof_verification_histogram = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
        let apply_histogram = Histogram::new(Buckets::LOCAL.into_iter());

        let metrics = Self {
            valid_batches_received: Counter::default(),
            invalid_batches_received: Counter::default(),
            operations_fetched: Counter::default(),
            _fetch_duration: Timed::new(fetch_histogram.clone(), Arc::new(context.clone())),
            proof_verification_duration: Timed::new(
                proof_verification_histogram.clone(),
                Arc::new(context.clone()),
            ),
            apply_duration: Timed::new(apply_histogram.clone(), Arc::new(context.clone())),
        };

        // Register metrics.
        context.register(
            "valid_batches_received",
            "Number of valid operation batches processed during ADB sync",
            metrics.valid_batches_received.clone(),
        );
        context.register(
            "invalid_batches_received",
            "Number of invalid operation batches encountered during ADB sync",
            metrics.invalid_batches_received.clone(),
        );
        context.register(
            "operations_fetched",
            "Total number of operations fetched during ADB sync",
            metrics.operations_fetched.clone(),
        );
        context.register(
            "fetch_duration_seconds",
            "Histogram of durations spent fetching operation batches during ADB sync",
            fetch_histogram,
        );
        context.register(
            "proof_verification_duration_seconds",
            "Histogram of durations spent verifying proofs during ADB sync",
            proof_verification_histogram,
        );
        context.register(
            "apply_duration_seconds",
            "Histogram of durations spent applying operations during ADB sync",
            apply_histogram,
        );

        metrics
    }
}

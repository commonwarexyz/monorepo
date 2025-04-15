use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};

pub mod audited;
pub mod memory;
pub mod tokio;

pub struct Metrics {
    pub open_blobs: Gauge,
    pub storage_reads: Counter,
    pub storage_read_bytes: Counter,
    pub storage_writes: Counter,
    pub storage_write_bytes: Counter,
}

impl Metrics {
    /// Initialize the `Metrics` struct and register the metrics in the provided registry.
    pub fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bytes: Counter::default(),
            storage_writes: Counter::default(),
            storage_write_bytes: Counter::default(),
        };

        registry.register(
            "open_blobs",
            "Number of open blobs",
            metrics.open_blobs.clone(),
        );
        registry.register(
            "storage_reads",
            "Total number of disk reads",
            metrics.storage_reads.clone(),
        );
        registry.register(
            "storage_read_bytes",
            "Total amount of data read from disk",
            metrics.storage_read_bytes.clone(),
        );
        registry.register(
            "storage_writes",
            "Total number of disk writes",
            metrics.storage_writes.clone(),
        );
        registry.register(
            "storage_write_bytes",
            "Total amount of data written to disk",
            metrics.storage_write_bytes.clone(),
        );

        metrics
    }
}

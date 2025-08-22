//! Process metrics collection.

use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use std::{future::Future, time::Duration};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

/// The interval at which to update process metrics.
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// Process metrics collector.
pub struct Metrics {
    /// Process ID.
    pub pid: u32,
    /// Resident set size in bytes.
    pub rss: Gauge,
    /// Virtual memory size in bytes.
    pub virtual_memory: Gauge,

    /// System information handle.
    system: System,
}

impl Metrics {
    /// Initialize process metrics and register them with the given registry.
    pub fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            pid: std::process::id(),
            rss: Gauge::default(),
            virtual_memory: Gauge::default(),

            system: System::new(),
        };

        // Register all metrics
        registry.register(
            "process_rss",
            "Resident set size of the current process",
            metrics.rss.clone(),
        );
        registry.register(
            "process_virtual_memory",
            "Virtual memory size of the current process",
            metrics.virtual_memory.clone(),
        );

        metrics
    }

    /// Update all process metrics.
    fn update(&mut self) {
        // Refresh process information
        let pid = sysinfo::Pid::from_u32(self.pid);
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing().with_memory(),
        );

        // If the process exists, update the metrics
        if let Some(process) = self.system.process(pid) {
            self.rss.set(process.memory() as i64);
            self.virtual_memory.set(process.virtual_memory() as i64);
        }
    }

    /// Update process metrics periodically.
    ///
    /// This function takes a sleep function as a parameter to allow different runtimes
    /// to provide their own implementation.
    pub async fn collect<F, Fut>(mut self, sleep_fn: F)
    where
        F: Fn(Duration) -> Fut,
        Fut: Future<Output = ()>,
    {
        loop {
            self.update();
            sleep_fn(UPDATE_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_metrics_init() {
        let mut registry = Registry::default();
        let mut metrics = Metrics::init(&mut registry);

        // Update metrics
        metrics.update();

        // Ensure that the process ID is set
        assert_ne!(metrics.pid, 0);

        // Check that RSS is reasonable (> 1MB for a running process)
        let rss = metrics.rss.get();
        assert!(rss > 1_000_000, "RSS should be > 1MB, got: {rss}");

        // Check that virtual memory is >= RSS
        let virt = metrics.virtual_memory.get();
        assert!(virt >= rss, "Virtual memory should be >= RSS");

        // Allocate some memory
        let mut vec = vec![0; 10 * 1024 * 1024]; // 10MB
        vec.push(1);

        // Update metrics
        metrics.update();

        // Check that the metrics are updated
        let new_rss = metrics.rss.get();
        assert!(new_rss > rss, "RSS should be > {rss}");

        // Check that virtual memory is updated
        let new_virt = metrics.virtual_memory.get();
        assert!(new_virt > virt, "Virtual memory should be > {virt}");
    }
}

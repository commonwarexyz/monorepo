//! Process metrics collection.

use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

/// Process metrics collector.
pub struct Metrics {
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
    pub fn update(&mut self) {
        // Refresh process information
        let pid = sysinfo::Pid::from(std::process::id() as usize);
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

        // Check that RSS is reasonable (> 1MB for a running process)
        let rss = metrics.rss.get();
        assert!(rss > 1_000_000, "RSS should be > 1MB, got: {rss}");

        // Check that virtual memory is >= RSS
        let virt = metrics.virtual_memory.get();
        assert!(virt >= rss, "Virtual memory should be >= RSS");
    }
}

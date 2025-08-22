//! System metrics collection for process monitoring.

use prometheus_client::{metrics::gauge::Gauge, registry::Registry};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

/// System metrics collector.
pub struct Metrics {
    /// Resident set size in bytes.
    pub process_rss_bytes: Gauge,
    /// Virtual memory size in bytes.
    pub process_virtual_memory_bytes: Gauge,

    /// System information handle.
    system: System,
}

impl Metrics {
    /// Initialize system metrics and register them with the given registry.
    pub fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            process_rss_bytes: Gauge::default(),
            process_virtual_memory_bytes: Gauge::default(),

            system: System::new(),
        };

        // Register all metrics
        registry.register(
            "process_rss_bytes",
            "Resident set size of the current process in bytes",
            metrics.process_rss_bytes.clone(),
        );
        registry.register(
            "process_virtual_memory_bytes",
            "Virtual memory size of the current process in bytes",
            metrics.process_virtual_memory_bytes.clone(),
        );

        metrics
    }

    /// Update all system metrics.
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
            self.process_rss_bytes.set(process.memory() as i64);
            self.process_virtual_memory_bytes
                .set(process.virtual_memory() as i64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_metrics_init() {
        let mut registry = Registry::default();
        let mut metrics = Metrics::init(&mut registry);

        // Update metrics
        metrics.update();

        // Check that RSS is reasonable (> 1MB for a running process)
        let rss = metrics.process_rss_bytes.get();
        assert!(rss > 1_000_000, "RSS should be > 1MB, got: {rss}");

        // Check that virtual memory is >= RSS
        let virt = metrics.process_virtual_memory_bytes.get();
        assert!(virt >= rss, "Virtual memory should be >= RSS");
    }
}

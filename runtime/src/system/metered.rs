//! System metrics collection for process monitoring.

use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use sysinfo::{CpuRefreshKind, ProcessRefreshKind, System};

/// System metrics collector.
pub struct Metrics {
    /// Resident set size in bytes.
    pub process_rss_bytes: Gauge,
    /// Virtual memory size in bytes.
    pub process_virtual_memory_bytes: Gauge,
    /// CPU usage percentage (0-100 * number of cores).
    pub process_cpu_percent: Gauge,
    /// Number of threads.
    pub process_threads: Gauge,
    /// Total CPU time in seconds.
    pub process_cpu_seconds_total: Counter,
    /// Number of open file descriptors (Unix only).
    #[cfg(unix)]
    pub process_open_fds: Gauge,

    /// System information handle.
    system: System,
    /// Last recorded CPU time for delta calculation.
    last_cpu_time: u64,
}

impl Metrics {
    /// Initialize system metrics and register them with the given registry.
    pub fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            process_rss_bytes: Gauge::default(),
            process_virtual_memory_bytes: Gauge::default(),
            process_cpu_percent: Gauge::default(),
            process_threads: Gauge::default(),
            process_cpu_seconds_total: Counter::default(),
            #[cfg(unix)]
            process_open_fds: Gauge::default(),

            system: System::new(),
            last_cpu_time: 0,
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
        registry.register(
            "process_cpu_percent",
            "CPU usage of the current process as a percentage",
            metrics.process_cpu_percent.clone(),
        );
        registry.register(
            "process_threads",
            "Number of threads in the current process",
            metrics.process_threads.clone(),
        );
        registry.register(
            "process_cpu_seconds_total",
            "Total CPU time spent by the process in seconds",
            metrics.process_cpu_seconds_total.clone(),
        );
        #[cfg(unix)]
        registry.register(
            "process_open_fds",
            "Number of open file descriptors",
            metrics.process_open_fds.clone(),
        );

        metrics
    }

    /// Update all system metrics.
    pub fn update(&mut self) {
        let pid = sysinfo::Pid::from(std::process::id() as usize);

        // Refresh process information
        self.system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing()
                .with_memory()
                .with_cpu()
                .with_disk_usage(),
        );

        // Refresh CPU information for accurate CPU percentage
        self.system
            .refresh_cpu_specifics(CpuRefreshKind::everything());

        if let Some(process) = self.system.process(pid) {
            // Memory metrics (convert KB to bytes)
            self.process_rss_bytes.set((process.memory() * 1024) as i64);
            self.process_virtual_memory_bytes
                .set((process.virtual_memory() * 1024) as i64);

            // CPU metrics
            self.process_cpu_percent.set(process.cpu_usage() as i64);

            // Thread count - sysinfo doesn't provide direct thread count
            // We'll use a placeholder for now
            self.process_threads.set(1);

            // Total CPU time (convert to seconds)
            let cpu_time = process.run_time();
            if cpu_time > self.last_cpu_time {
                let delta = cpu_time - self.last_cpu_time;
                self.process_cpu_seconds_total.inc_by(delta);
                self.last_cpu_time = cpu_time;
            }

            // File descriptors (Unix only)
            #[cfg(unix)]
            {
                if let Ok(fd_count) = count_open_fds() {
                    self.process_open_fds.set(fd_count as i64);
                }
            }
        }
    }
}

/// Count open file descriptors on Unix systems.
#[cfg(unix)]
fn count_open_fds() -> Result<usize, std::io::Error> {
    use std::fs;

    let pid = std::process::id();
    let fd_dir = format!("/proc/{pid}/fd");

    // On Linux, count entries in /proc/PID/fd
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        return Ok(entries.count());
    }

    // On macOS, use lsof or similar (more complex)
    // For now, return an error on non-Linux systems
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "File descriptor counting not available on this platform",
    ))
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

        // Check thread count is at least 1
        let threads = metrics.process_threads.get();
        assert!(threads >= 1, "Should have at least 1 thread");
    }
}

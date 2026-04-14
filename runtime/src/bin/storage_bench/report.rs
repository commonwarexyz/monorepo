//! Statistics collection and reporting for `storage_bench`.

use crate::{config::Config, filesystem::backend_name};
use serde_json::json;
use std::time::Duration;

/// Aggregated stats for one worker stream.
#[derive(Default)]
pub struct WorkerStats {
    /// Number of completed operations.
    pub ops: u64,
    /// Number of bytes transferred.
    pub bytes: u64,
    /// Sampled per-operation latencies.
    pub latency_samples: Vec<Duration>,
}

impl WorkerStats {
    /// Record one completed operation without storing a latency sample.
    #[inline(always)]
    pub const fn record(&mut self, bytes: u64) {
        self.ops += 1;
        self.bytes += bytes;
    }

    /// Record one completed operation and retain a latency sample.
    #[inline(always)]
    pub fn record_latency_sample(&mut self, latency: Duration, bytes: u64) {
        self.record(bytes);
        self.latency_samples.push(latency);
    }

    /// Merge another worker's stats into this accumulator.
    pub fn merge(&mut self, mut other: Self) {
        self.ops += other.ops;
        self.bytes += other.bytes;
        self.latency_samples.append(&mut other.latency_samples);
    }
}

/// Derived metrics for one operation class.
struct OperationReport {
    /// Completed operations.
    ops: u64,
    /// Total bytes transferred.
    bytes: u64,
    /// Throughput in operations per second.
    ops_per_sec: f64,
    /// Throughput in MiB per second.
    mib_per_sec: f64,
    /// p50 latency.
    p50_latency: Duration,
    /// p95 latency.
    p95_latency: Duration,
    /// p99 latency.
    p99_latency: Duration,
}

impl OperationReport {
    /// Merge multiple workers and compute summary metrics.
    fn new(workers: Vec<WorkerStats>, elapsed: Duration) -> Self {
        let mut merged = WorkerStats::default();
        for w in workers {
            merged.merge(w);
        }
        merged.latency_samples.sort_unstable();
        let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
        let percentile = |pct: usize| {
            if merged.latency_samples.is_empty() {
                return Duration::ZERO;
            }
            merged.latency_samples[(merged.latency_samples.len() - 1) * pct / 100]
        };
        Self {
            ops: merged.ops,
            bytes: merged.bytes,
            ops_per_sec: merged.ops as f64 / elapsed_secs,
            mib_per_sec: (merged.bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs,
            p50_latency: percentile(50),
            p95_latency: percentile(95),
            p99_latency: percentile(99),
        }
    }

    fn print(&self, label: &str) {
        println!(
            "{label} ops={} bytes={} ops_per_sec={:.0} mib_per_sec={:.1} p50_us={:.1} p95_us={:.1} p99_us={:.1}",
            self.ops,
            self.bytes,
            self.ops_per_sec,
            self.mib_per_sec,
            self.p50_latency.as_nanos() as f64 / 1_000.0,
            self.p95_latency.as_nanos() as f64 / 1_000.0,
            self.p99_latency.as_nanos() as f64 / 1_000.0,
        );
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "ops": self.ops,
            "bytes": self.bytes,
            "ops_per_sec": self.ops_per_sec,
            "mib_per_sec": self.mib_per_sec,
            "p50_latency_ns": self.p50_latency.as_nanos() as u64,
            "p95_latency_ns": self.p95_latency.as_nanos() as u64,
            "p99_latency_ns": self.p99_latency.as_nanos() as u64,
        })
    }
}

/// Full benchmark report.
pub struct Report {
    /// Actual elapsed time, including any final end-of-run sync.
    elapsed: Duration,
    /// Read-side metrics, when present.
    read: Option<OperationReport>,
    /// Write-side metrics, when present.
    write: Option<OperationReport>,
    /// Final logical file size.
    final_file_size: u64,
}

impl Report {
    /// Build a report from worker stats.
    ///
    /// Pass `None` for the side that doesn't apply to this scenario.
    pub fn new(
        elapsed: Duration,
        read_workers: Option<Vec<WorkerStats>>,
        write_workers: Option<Vec<WorkerStats>>,
        final_file_size: u64,
    ) -> Self {
        Self {
            elapsed,
            read: read_workers.map(|w| OperationReport::new(w, elapsed)),
            write: write_workers.map(|w| OperationReport::new(w, elapsed)),
            final_file_size,
        }
    }

    /// Print a concise human-readable report.
    pub fn print_human(&self, cfg: &Config) {
        println!(
            "backend={} scenario={} elapsed_s={:.3}",
            backend_name(),
            cfg.scenario,
            self.elapsed.as_secs_f64(),
        );
        println!(
            "io_size={} inflight={} worker_threads={} global_queue_interval={} seed={} output={}",
            cfg.io_size,
            cfg.inflight,
            cfg.worker_threads,
            cfg.global_queue_interval
                .map_or_else(|| "default".to_string(), |value| value.to_string()),
            cfg.seed,
            cfg.output,
        );

        if let Some(file_size) = cfg.file_size {
            println!("file_size={file_size}");
        }
        println!("root={}", cfg.root.display());
        if let Some(cache) = cfg.cache {
            println!("cache={cache}");
        }
        if cfg.scenario.has_writes() {
            println!(
                "write_shape={} sync_every={}",
                cfg.write_shape, cfg.sync_mode
            );
        }

        if let Some(read) = &self.read {
            read.print("read");
        }
        if let Some(write) = &self.write {
            write.print("write");
        }
        println!("final_file_size={}", self.final_file_size);
    }

    /// Print a single JSON object for downstream processing.
    pub fn print_json(&self, cfg: &Config) {
        let json = json!({
            "backend": backend_name(),
            "scenario": cfg.scenario.to_string(),
            "duration_seconds": cfg.duration().as_secs(),
            "io_size": cfg.io_size,
            "inflight": cfg.inflight,
            "worker_threads": cfg.worker_threads,
            "global_queue_interval": cfg.global_queue_interval,
            "file_size": cfg.file_size,
            "root": cfg.root,
            "cache": cfg.cache.map(|mode| mode.to_string()),
            "write_shape": cfg.scenario.has_writes().then(|| cfg.write_shape.to_string()),
            "sync_every": cfg.scenario.has_writes().then(|| cfg.sync_mode.to_string()),
            "seed": cfg.seed,
            "elapsed_ns": self.elapsed.as_nanos() as u64,
            "read": self.read.as_ref().map(OperationReport::to_json),
            "write": self.write.as_ref().map(OperationReport::to_json),
            "final_file_size": self.final_file_size,
        });
        println!("{json}");
    }
}

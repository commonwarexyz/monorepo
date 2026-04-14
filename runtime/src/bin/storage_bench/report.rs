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
    /// Sampled per-operation latencies in nanoseconds.
    pub latency_samples_ns: Vec<u64>,
}

impl WorkerStats {
    /// Record one completed operation without storing a latency sample.
    #[inline(always)]
    pub const fn record(&mut self, bytes: u64) {
        self.ops += 1;
        self.bytes += bytes;
    }

    /// Record one completed operation and retain a latency sample.
    #[inline]
    pub fn record_latency_sample(&mut self, latency: Duration, bytes: u64) {
        self.record(bytes);
        self.latency_samples_ns
            .push(latency.as_nanos().min(u64::MAX as u128) as u64);
    }

    /// Merge another worker's stats into this accumulator.
    #[inline]
    pub fn merge(&mut self, mut other: Self) {
        self.ops += other.ops;
        self.bytes += other.bytes;
        self.latency_samples_ns
            .append(&mut other.latency_samples_ns);
    }
}

/// Derived metrics for one operation class.
pub struct OperationReport {
    /// Completed operations.
    ops: u64,
    /// Total bytes transferred.
    bytes: u64,
    /// Throughput in operations per second.
    ops_per_sec: f64,
    /// Throughput in MiB per second.
    mib_per_sec: f64,
    /// p50 latency in nanoseconds.
    p50_latency_ns: u64,
    /// p95 latency in nanoseconds.
    p95_latency_ns: u64,
    /// p99 latency in nanoseconds.
    p99_latency_ns: u64,
}

/// Full scenario report.
pub struct ScenarioReport {
    /// Actual elapsed time, including any final end-of-run sync.
    pub elapsed: Duration,
    /// Read-side metrics, when present.
    pub read: Option<OperationReport>,
    /// Write-side metrics, when present.
    pub write: Option<OperationReport>,
    /// Final logical file size.
    pub final_file_size: u64,
}

/// Merge the results of many worker futures.
pub fn merge_worker_results(
    results: Vec<Result<WorkerStats, String>>,
) -> Result<WorkerStats, String> {
    let mut merged = WorkerStats::default();
    for result in results {
        merged.merge(result?);
    }
    Ok(merged)
}

/// Convert accumulated worker stats into a report section.
pub fn summarize_operation(mut stats: WorkerStats, elapsed: Duration) -> OperationReport {
    stats.latency_samples_ns.sort_unstable();
    let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
    OperationReport {
        ops: stats.ops,
        bytes: stats.bytes,
        ops_per_sec: stats.ops as f64 / elapsed_secs,
        mib_per_sec: (stats.bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs,
        p50_latency_ns: percentile(&stats.latency_samples_ns, 50),
        p95_latency_ns: percentile(&stats.latency_samples_ns, 95),
        p99_latency_ns: percentile(&stats.latency_samples_ns, 99),
    }
}

/// Print a concise human-readable report.
pub fn print_human_report(cfg: &Config, report: &ScenarioReport) {
    println!(
        "backend={} scenario={} elapsed_s={:.3}",
        backend_name(),
        cfg.scenario,
        report.elapsed.as_secs_f64(),
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

    if let Some(read) = &report.read {
        print_operation("read", read);
    }
    if let Some(write) = &report.write {
        print_operation("write", write);
    }
    println!("final_file_size={}", report.final_file_size);
}

/// Print a single JSON object for downstream processing.
pub fn print_json_report(cfg: &Config, report: &ScenarioReport) {
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
        "elapsed_ns": report.elapsed.as_nanos().min(u64::MAX as u128) as u64,
        "read": report.read.as_ref().map(operation_json),
        "write": report.write.as_ref().map(operation_json),
        "final_file_size": report.final_file_size,
    });
    println!("{json}");
}

/// Return the nearest-rank percentile from a sorted latency vector.
fn percentile(sorted: &[u64], pct: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct as usize) / 100;
    sorted[idx]
}

fn print_operation(label: &str, r: &OperationReport) {
    println!(
        "{label} ops={} bytes={} ops_per_sec={:.0} mib_per_sec={:.1} p50_us={:.1} p95_us={:.1} p99_us={:.1}",
        r.ops,
        r.bytes,
        r.ops_per_sec,
        r.mib_per_sec,
        r.p50_latency_ns as f64 / 1_000.0,
        r.p95_latency_ns as f64 / 1_000.0,
        r.p99_latency_ns as f64 / 1_000.0,
    );
}

fn operation_json(r: &OperationReport) -> serde_json::Value {
    json!({
        "ops": r.ops,
        "bytes": r.bytes,
        "ops_per_sec": r.ops_per_sec,
        "mib_per_sec": r.mib_per_sec,
        "p50_latency_ns": r.p50_latency_ns,
        "p95_latency_ns": r.p95_latency_ns,
        "p99_latency_ns": r.p99_latency_ns,
    })
}

//! Statistics collection and reporting.

use crate::{
    config::{Config, Workload},
    filesystem::{FileMetrics, backend_name},
};
use serde_json::json;
use std::time::Duration;

/// Aggregated stats for one worker stream.
#[derive(Default)]
pub struct Stats {
    /// Number of completed operations.
    pub ops: u64,
    /// Number of bytes transferred.
    pub bytes: u64,
    /// Sampled per-operation latencies.
    pub latency_samples: Vec<Duration>,
    /// Durability barriers issued by the loop.
    pub syncs: u64,
    /// Wall time spent awaiting those barriers.
    pub sync_elapsed: Duration,
    /// Time from batch publication start until the durable decision return.
    pub decision_return_samples: Vec<Duration>,
    /// Time from batch publication start through full completion-handle cleanup.
    pub full_completion_samples: Vec<Duration>,
}

impl Stats {
    /// Record one completed operation, optionally with a latency sample.
    #[inline(always)]
    pub fn record(&mut self, bytes: u64, latency: Option<Duration>) {
        self.ops += 1;
        self.bytes += bytes;
        if let Some(latency) = latency {
            self.latency_samples.push(latency);
        }
    }

    /// Merge another worker's stats into this accumulator.
    pub fn merge(&mut self, mut other: Self) {
        self.ops += other.ops;
        self.bytes += other.bytes;
        self.latency_samples.append(&mut other.latency_samples);
        self.syncs += other.syncs;
        self.sync_elapsed += other.sync_elapsed;
        self.decision_return_samples
            .append(&mut other.decision_return_samples);
        self.full_completion_samples
            .append(&mut other.full_completion_samples);
    }

    #[inline(always)]
    pub fn record_sync(&mut self, elapsed: Duration) {
        self.syncs += 1;
        self.sync_elapsed += elapsed;
    }

    /// Record the durable-decision and completion-handle boundaries of one atomic batch.
    pub fn record_publication(&mut self, decision_return: Duration, full_completion: Duration) {
        self.decision_return_samples.push(decision_return);
        self.full_completion_samples.push(full_completion);
    }
}

/// Latency distribution for a separately measured operation phase.
struct PhaseReport {
    samples: u64,
    elapsed: Duration,
    p50_latency: Duration,
    p95_latency: Duration,
    p99_latency: Duration,
}

impl PhaseReport {
    fn new(mut samples: Vec<Duration>) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        let percentile = |pct: usize| samples[(samples.len() - 1) * pct / 100];
        Some(Self {
            samples: samples.len() as u64,
            elapsed: samples.iter().sum(),
            p50_latency: percentile(50),
            p95_latency: percentile(95),
            p99_latency: percentile(99),
        })
    }

    fn print(&self, label: &str) {
        println!(
            "{label} samples={} elapsed_s={:.6} mean_us={:.1} p50_us={:.1} p95_us={:.1} p99_us={:.1}",
            self.samples,
            self.elapsed.as_secs_f64(),
            self.elapsed.as_nanos() as f64 / self.samples as f64 / 1_000.0,
            self.p50_latency.as_nanos() as f64 / 1_000.0,
            self.p95_latency.as_nanos() as f64 / 1_000.0,
            self.p99_latency.as_nanos() as f64 / 1_000.0,
        );
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "samples": self.samples,
            "elapsed_ns": self.elapsed.as_nanos() as u64,
            "mean_latency_ns": self.elapsed.as_nanos() as u64 / self.samples,
            "p50_latency_ns": self.p50_latency.as_nanos() as u64,
            "p95_latency_ns": self.p95_latency.as_nanos() as u64,
            "p99_latency_ns": self.p99_latency.as_nanos() as u64,
        })
    }
}

/// Derived metrics for one operation class.
struct OperationReport {
    /// Elapsed operation time used as the throughput denominator.
    elapsed: Duration,
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
    /// Durability barriers and total time spent awaiting them.
    syncs: u64,
    sync_elapsed: Duration,
    /// Atomic-batch durable decision-return latency.
    decision_return: Option<PhaseReport>,
    /// Atomic-batch latency through full completion-handle cleanup.
    full_completion: Option<PhaseReport>,
}

impl OperationReport {
    /// Merge multiple workers and compute summary metrics.
    fn new(workers: Vec<Stats>, elapsed: Duration) -> Self {
        let mut merged = Stats::default();
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
            elapsed,
            ops: merged.ops,
            bytes: merged.bytes,
            ops_per_sec: merged.ops as f64 / elapsed_secs,
            mib_per_sec: (merged.bytes as f64 / (1024.0 * 1024.0)) / elapsed_secs,
            p50_latency: percentile(50),
            p95_latency: percentile(95),
            p99_latency: percentile(99),
            syncs: merged.syncs,
            sync_elapsed: merged.sync_elapsed,
            decision_return: PhaseReport::new(merged.decision_return_samples),
            full_completion: PhaseReport::new(merged.full_completion_samples),
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
        if self.syncs != 0 {
            println!(
                "{label}_sync count={} elapsed_s={:.6} mean_us={:.1}",
                self.syncs,
                self.sync_elapsed.as_secs_f64(),
                self.sync_elapsed.as_nanos() as f64 / self.syncs as f64 / 1_000.0,
            );
        }
        if let Some(decision_return) = &self.decision_return {
            decision_return.print(&format!("{label}_decision_return"));
        }
        if let Some(full_completion) = &self.full_completion {
            full_completion.print(&format!("{label}_full_completion"));
        }
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
            "sync_count": self.syncs,
            "sync_elapsed_ns": self.sync_elapsed.as_nanos() as u64,
            "decision_return": self.decision_return.as_ref().map(PhaseReport::to_json),
            "full_completion": self.full_completion.as_ref().map(PhaseReport::to_json),
        })
    }

    fn to_paired_json(&self) -> serde_json::Value {
        let mut report = self.to_json();
        report
            .as_object_mut()
            .expect("operation report must serialize as an object")
            .insert("elapsed_ns".into(), json!(self.elapsed.as_nanos() as u64));
        report
    }
}

/// Per-side metrics for an in-process ordinary-versus-atomic comparison.
struct PairedReport {
    ordinary: OperationReport,
    atomic: OperationReport,
}

impl PairedReport {
    fn new(
        ordinary: Stats,
        ordinary_elapsed: Duration,
        atomic: Stats,
        atomic_elapsed: Duration,
    ) -> Self {
        Self {
            ordinary: OperationReport::new(vec![ordinary], ordinary_elapsed),
            atomic: OperationReport::new(vec![atomic], atomic_elapsed),
        }
    }

    fn throughput_ratio(&self) -> f64 {
        self.atomic.ops_per_sec / self.ordinary.ops_per_sec.max(f64::EPSILON)
    }

    fn print(&self) {
        println!(
            "paired_baseline=true ordinary_elapsed_s={:.6} atomic_elapsed_s={:.6} atomic_to_ordinary_throughput_ratio={:.6}",
            self.ordinary.elapsed.as_secs_f64(),
            self.atomic.elapsed.as_secs_f64(),
            self.throughput_ratio(),
        );
        self.ordinary.print("ordinary");
        self.atomic.print("atomic");
    }
}

/// Full benchmark report.
pub struct Report {
    /// Actual elapsed time, including any final end-of-run sync.
    elapsed: Duration,
    /// Time spent in the operation loop used for throughput calculations.
    hot_elapsed: Duration,
    /// Time spent advancing the final durability frontier, when measured separately.
    frontier_sync_elapsed: Option<Duration>,
    /// Read-side metrics, when present.
    read: Option<OperationReport>,
    /// Write-side metrics, when present.
    write: Option<OperationReport>,
    /// Side-specific metrics for paired ordinary and atomic operations.
    paired: Option<PairedReport>,
    /// Final logical file size.
    final_file_size: u64,
    /// Atomic-append protocol selected by the filesystem, when applicable.
    atomic_protocol: Option<&'static str>,
    /// Raw and physically allocated file sizes after the workload.
    file_metrics: Option<FileMetrics>,
    /// Resident memory before and during the workload while its blob remains open.
    resident_memory: Option<(u64, u64)>,
}

impl Report {
    /// Build a report from worker stats.
    ///
    /// Pass `None` for the side that doesn't apply to this workload.
    pub fn new(
        hot_elapsed: Duration,
        frontier_sync_elapsed: Option<Duration>,
        read_workers: Option<Vec<Stats>>,
        write_workers: Option<Vec<Stats>>,
        final_file_size: u64,
    ) -> Self {
        let elapsed = hot_elapsed + frontier_sync_elapsed.unwrap_or_default();
        Self {
            elapsed,
            hot_elapsed,
            frontier_sync_elapsed,
            read: read_workers.map(|w| OperationReport::new(w, hot_elapsed)),
            write: write_workers.map(|w| OperationReport::new(w, hot_elapsed)),
            paired: None,
            final_file_size,
            atomic_protocol: None,
            file_metrics: None,
            resident_memory: None,
        }
    }

    /// Build a report whose paired sides use independent throughput denominators.
    pub fn new_paired(
        hot_elapsed: Duration,
        ordinary: Stats,
        ordinary_elapsed: Duration,
        atomic: Stats,
        atomic_elapsed: Duration,
        final_file_size: u64,
    ) -> Self {
        Self {
            elapsed: hot_elapsed,
            hot_elapsed,
            frontier_sync_elapsed: None,
            read: None,
            write: None,
            paired: Some(PairedReport::new(
                ordinary,
                ordinary_elapsed,
                atomic,
                atomic_elapsed,
            )),
            final_file_size,
            atomic_protocol: None,
            file_metrics: None,
            resident_memory: None,
        }
    }

    /// Record the atomic-append protocol observed by the benchmark harness.
    pub const fn set_atomic_protocol(&mut self, protocol: &'static str) {
        self.atomic_protocol = Some(protocol);
    }

    pub const fn set_file_metrics(&mut self, metrics: FileMetrics) {
        self.file_metrics = Some(metrics);
    }

    pub const fn set_resident_memory(&mut self, before: Option<u64>, after: Option<u64>) {
        self.resident_memory = match (before, after) {
            (Some(before), Some(after)) => Some((before, after)),
            _ => None,
        };
    }

    /// Print a concise human-readable report.
    pub fn print_human(&self, cfg: &Config) {
        println!(
            "backend={} workload={} elapsed_s={:.3} hot_elapsed_s={:.3} frontier_sync_s={}",
            backend_name(),
            cfg.workload,
            self.elapsed.as_secs_f64(),
            self.hot_elapsed.as_secs_f64(),
            self.frontier_sync_elapsed.map_or_else(
                || "n/a".to_string(),
                |elapsed| format!("{:.6}", elapsed.as_secs_f64())
            ),
        );
        println!(
            "io_size={} operations={} inflight={} worker_threads={} global_queue_interval={} seed={} output={}",
            cfg.io_size(),
            cfg.operations
                .map_or_else(|| "duration".to_string(), |value| value.to_string()),
            cfg.inflight,
            cfg.worker_threads,
            cfg.global_queue_interval
                .map_or_else(|| "default".to_string(), |value| value.to_string()),
            cfg.seed,
            cfg.output,
        );
        if cfg.workload.is_atomic() {
            println!(
                "integrity_mode={} chunk_data_size={}",
                cfg.integrity_mode,
                cfg.chunk_data_size()
            );
        }

        if let Some(file_size) = cfg.file_size {
            println!("file_size={file_size}");
        }
        if cfg.workload.is_multi_blob_append() {
            let bytes_per_op = cfg.io_size() as u64 * cfg.blobs() as u64 * cfg.appends_per_batch();
            let completion = if cfg.paired_baseline {
                "side_specific"
            } else if cfg.workload == Workload::WriteAtomicBatchAppend {
                "full_batch_handle"
            } else {
                "all_blob_syncs"
            };
            println!(
                "blobs={} appends_per_batch={} operation_unit=n_blob_durable_group bytes_per_op={} operation_latency={completion}",
                cfg.blobs(),
                cfg.appends_per_batch(),
                bytes_per_op
            );
            if cfg.paired_baseline {
                println!(
                    "ordinary_operation_latency=all_blob_syncs atomic_operation_latency=full_batch_handle"
                );
            }
        }
        println!("root={}", cfg.root.display());
        if let Some(cache) = cfg.cache {
            println!("cache={cache}");
        }
        if cfg.workload.has_writes() {
            println!("write_shape={}", cfg.write_shape);
            if matches!(
                cfg.workload,
                Workload::WriteAppend | Workload::WriteAtomicAppend
            ) {
                println!("dont_cache={}", cfg.dont_cache);
            }
            if !cfg.workload.is_multi_blob_append() {
                if cfg.workload == Workload::WriteSync {
                    println!("sync_method={}", cfg.sync_method);
                } else {
                    println!("sync_every={}", cfg.sync_mode);
                }
            }
        }
        if let Some(protocol) = self.atomic_protocol {
            if cfg.workload == Workload::WriteAtomicBatchAppend {
                println!(
                    "atomic_protocol={protocol} atomic_phase=prepared_root durability_frontier=decision_return full_completion=batch_handle byte_accounting=logical_group_payload"
                );
            } else {
                println!(
                    "atomic_protocol={protocol} atomic_phase=pending_append durability_frontier=blob_sync full_completion=blob_sync byte_accounting=logical_payload"
                );
            }
        }
        if let Some(metrics) = self.file_metrics {
            println!(
                "measured_file_count={} raw_file_size={} allocated_file_size={}",
                metrics.file_count, metrics.raw_len, metrics.allocated_bytes
            );
        }
        if let Some((before, after)) = self.resident_memory {
            println!(
                "rss_before={} rss_after={} rss_delta={}",
                before,
                after,
                i128::from(after) - i128::from(before)
            );
        }

        if let Some(read) = &self.read {
            read.print("read");
        }
        if let Some(write) = &self.write {
            write.print("write");
        }
        if let Some(paired) = &self.paired {
            paired.print();
        }
        println!("final_file_size={}", self.final_file_size);
    }

    /// Print a single JSON object for downstream processing.
    pub fn print_json(&self, cfg: &Config) {
        let is_group = cfg.workload.is_multi_blob_append();
        let is_atomic_batch = cfg.workload == Workload::WriteAtomicBatchAppend;
        let paired_baseline = self.paired.as_ref().map(|paired| {
            json!({
                "ordinary_operation_latency": "all_blob_syncs",
                "atomic_operation_latency": "full_batch_handle",
                "ordinary": paired.ordinary.to_paired_json(),
                "atomic": paired.atomic.to_paired_json(),
                "atomic_to_ordinary_throughput_ratio": paired.throughput_ratio(),
            })
        });
        let mut json = json!({
            "backend": backend_name(),
            "workload": cfg.workload.to_string(),
            "duration_seconds": cfg.operations.is_none().then(|| cfg.duration().as_secs()),
            "operations_per_worker": cfg.operations,
            "io_size": cfg.io_size(),
            "integrity_mode": cfg.workload.is_atomic().then(|| cfg.integrity_mode.to_string()),
            "chunk_data_size": cfg.workload.is_atomic().then(|| cfg.chunk_data_size()),
            "blobs": is_group.then(|| cfg.blobs()),
            "appends_per_batch": is_group.then(|| cfg.appends_per_batch()),
            "bytes_per_op": is_group.then(|| {
                cfg.io_size() as u64 * cfg.blobs() as u64 * cfg.appends_per_batch()
            }),
            "operation_unit": is_group.then_some("n_blob_durable_group"),
            "operation_latency": is_group.then_some(if cfg.paired_baseline {
                "side_specific"
            } else if is_atomic_batch {
                "full_batch_handle"
            } else {
                "all_blob_syncs"
            }),
            "inflight": cfg.inflight,
            "worker_threads": cfg.worker_threads,
            "global_queue_interval": cfg.global_queue_interval,
            "file_size": cfg.file_size,
            "root": cfg.root,
            "cache": cfg.cache.map(|mode| mode.to_string()),
            "write_shape": cfg.workload.has_writes().then(|| cfg.write_shape.to_string()),
            "dont_cache": matches!(cfg.workload, Workload::WriteAppend | Workload::WriteAtomicAppend)
                .then_some(cfg.dont_cache),
            "sync_every": (cfg.workload.has_writes()
                && cfg.workload != Workload::WriteSync
                && !is_group)
                .then(|| cfg.sync_mode.to_string()),
            "sync_method": (cfg.workload == Workload::WriteSync)
                .then(|| cfg.sync_method.to_string()),
            "atomic_protocol": self.atomic_protocol,
            "atomic_phase": self.atomic_protocol.map(|_| if is_atomic_batch {
                "prepared_root"
            } else {
                "pending_append"
            }),
            "durability_frontier": if is_group {
                Some(if is_atomic_batch { "decision_return" } else { "all_blob_syncs" })
            } else {
                self.atomic_protocol.map(|_| "blob_sync")
            },
            "full_completion": if is_group {
                Some(if is_atomic_batch { "batch_handle" } else { "all_blob_syncs" })
            } else {
                self.atomic_protocol.map(|_| "blob_sync")
            },
            "byte_accounting": if is_group {
                Some("logical_group_payload")
            } else {
                self.atomic_protocol.map(|_| "logical_payload")
            },
            "measured_file_count": self.file_metrics.map(|metrics| metrics.file_count),
            "raw_file_size": self.file_metrics.map(|metrics| metrics.raw_len),
            "allocated_file_size": self.file_metrics.map(|metrics| metrics.allocated_bytes),
            "rss_before": self.resident_memory.map(|(before, _)| before),
            "rss_after": self.resident_memory.map(|(_, after)| after),
            "rss_delta": self.resident_memory.map(|(before, after)| i128::from(after) - i128::from(before)),
            "seed": cfg.seed,
            "elapsed_ns": self.elapsed.as_nanos() as u64,
            "hot_elapsed_ns": self.hot_elapsed.as_nanos() as u64,
            "frontier_sync_ns": self.frontier_sync_elapsed.map(|elapsed| elapsed.as_nanos() as u64),
            "read": self.read.as_ref().map(OperationReport::to_json),
            "write": self.write.as_ref().map(OperationReport::to_json),
            "final_file_size": self.final_file_size,
            "final_file_size_scope": is_group.then_some(if cfg.paired_baseline {
                "both_groups_all_participants"
            } else {
                "all_participants"
            }),
        });
        if let Some(paired_baseline) = paired_baseline {
            json.as_object_mut()
                .expect("benchmark report must serialize as an object")
                .insert("paired_baseline".into(), paired_baseline);
        }
        println!("{json}");
    }
}

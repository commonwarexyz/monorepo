//! Statistics collection and reporting.

use crate::{
    config::{Config, ReadApi, Workload},
    filesystem::backend_name,
};
use commonware_allocator::mimalloc::{Effective, Purge, Stats as AllocatorStats, Status};
use serde_json::json;
use std::time::Duration;

fn allocator_config() -> serde_json::Value {
    let effective = Effective::read();
    let status = Status::read();
    let requested = crate::GLOBAL.config();
    json!({
        "name": "mimalloc",
        "configured": status.configured,
        "requested_purge_delay_ns": match requested.purge { Purge::After(delay) => Some(delay.as_nanos() as u64), _ => None },
        "requested_pinned_reserve_bytes": requested.reserve.filter(|reserve| reserve.pinned).map(|reserve| reserve.bytes),
        "reserve_outcome": format!("{:?}", status.reserve),
        "pinned_bytes": AllocatorStats::read().map(|stats| stats.pinned_bytes),
        "purge_delay_ns": effective.purge.map(|duration| duration.as_nanos() as u64),
        "purge_decommits": effective.purge_decommits,
        "arena_eager_commit": effective.arena_eager_commit,
        "allow_large_os_pages": effective.allow_large_os_pages,
        "transparent_huge_pages": effective.transparent_huge_pages,
        "arena_reserve": effective.arena_reserve,
        "arena_max_object_size": effective.arena_max_object_size,
    })
}

/// Aggregated stats for one worker stream.
#[derive(Default)]
pub struct Stats {
    /// Completed read ranges or write operations.
    pub ops: u64,
    /// Number of bytes transferred.
    pub bytes: u64,
    /// Sampled per-operation latencies.
    pub latency_samples: Vec<Duration>,
    /// Completed read API calls.
    pub calls: u64,
    /// Sampled read API call latencies.
    pub call_latency_samples: Vec<Duration>,
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

    /// Record completion of one API call.
    pub fn record_call(&mut self, latency: Option<Duration>) {
        self.calls += 1;
        if let Some(latency) = latency {
            self.call_latency_samples.push(latency);
        }
    }

    /// Merge another worker's stats into this accumulator.
    pub fn merge(&mut self, mut other: Self) {
        self.calls += other.calls;
        self.call_latency_samples
            .append(&mut other.call_latency_samples);
        self.ops += other.ops;
        self.bytes += other.bytes;
        self.latency_samples.append(&mut other.latency_samples);
    }
}

/// Derived metrics for one operation class.
struct OperationReport {
    /// Completed read ranges or write operations.
    ops: u64,
    /// Completed read API calls.
    calls: u64,
    /// Call latency percentiles (p50, p95, p99).
    call_latency: [Duration; 3],
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
    fn new(workers: Vec<Stats>, elapsed: Duration) -> Self {
        let mut merged = Stats::default();
        for w in workers {
            merged.merge(w);
        }
        merged.latency_samples.sort_unstable();
        merged.call_latency_samples.sort_unstable();
        let call_latency = [50, 95, 99].map(|pct| {
            if merged.call_latency_samples.is_empty() {
                Duration::ZERO
            } else {
                merged.call_latency_samples[(merged.call_latency_samples.len() - 1) * pct / 100]
            }
        });
        let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
        let percentile = |pct: usize| {
            if merged.latency_samples.is_empty() {
                return Duration::ZERO;
            }
            merged.latency_samples[(merged.latency_samples.len() - 1) * pct / 100]
        };
        Self {
            ops: merged.ops,
            calls: merged.calls,
            call_latency,
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
            "{label} calls={} call_p50_us={:.1} call_p95_us={:.1} call_p99_us={:.1}",
            self.calls,
            self.call_latency[0].as_nanos() as f64 / 1_000.0,
            self.call_latency[1].as_nanos() as f64 / 1_000.0,
            self.call_latency[2].as_nanos() as f64 / 1_000.0
        );
        println!(
            "{label} ops={} bytes={} ops_per_sec={:.0} mib_per_sec={:.1} range_p50_us={:.1} range_p95_us={:.1} range_p99_us={:.1}",
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
            "calls": self.calls,
            "ranges_per_call": (self.calls != 0).then(|| self.ops as f64 / self.calls as f64),
            "call_p50_latency_ns": self.call_latency[0].as_nanos() as u64,
            "call_p95_latency_ns": self.call_latency[1].as_nanos() as u64,
            "call_p99_latency_ns": self.call_latency[2].as_nanos() as u64,
            "bytes": self.bytes,
            "ops_per_sec": self.ops_per_sec,
            "mib_per_sec": self.mib_per_sec,
            "range_p50_latency_ns": self.p50_latency.as_nanos() as u64,
            "range_p95_latency_ns": self.p95_latency.as_nanos() as u64,
            "range_p99_latency_ns": self.p99_latency.as_nanos() as u64,
        })
    }
}

/// Read API shape supplied by the workload for one phase.
pub struct PhaseShape {
    /// Read call used for the phase.
    pub read_api: ReadApi,
    /// Maximum outstanding ranges in the phase.
    pub outstanding_ranges: usize,
}

/// Full benchmark report.
pub struct Report {
    /// Actual timed phase duration.
    elapsed: Duration,
    /// Read-side metrics, when present.
    read: Option<OperationReport>,
    /// Write-side metrics, when present.
    write: Option<OperationReport>,
    /// Final logical file size.
    final_file_size: u64,
    phases: serde_json::Map<String, serde_json::Value>,
    measurements: serde_json::Value,
    idle_baseline: serde_json::Value,
}

impl Report {
    /// Build a report from worker stats.
    ///
    /// Pass `None` for the side that doesn't apply to this workload.
    pub fn new(
        elapsed: Duration,
        read_workers: Option<Vec<Stats>>,
        write_workers: Option<Vec<Stats>>,
        final_file_size: u64,
    ) -> Self {
        Self {
            elapsed,
            read: read_workers.map(|w| OperationReport::new(w, elapsed)),
            write: write_workers.map(|w| OperationReport::new(w, elapsed)),
            final_file_size,
            phases: serde_json::Map::new(),
            measurements: serde_json::Value::Null,
            idle_baseline: serde_json::Value::Null,
        }
    }

    /// Attach a separately timed read phase.
    pub fn with_phase(
        mut self,
        name: &str,
        elapsed: Duration,
        stats: Stats,
        measurements: serde_json::Value,
        shape: PhaseShape,
    ) -> Self {
        self.phases.insert(
            name.to_string(),
            json!({
                "elapsed_ns": elapsed.as_nanos() as u64,
                "read": OperationReport::new(vec![stats], elapsed).to_json(),
                "measurements": measurements,
                "read_api": shape.read_api.to_string(),
                "outstanding_ranges": shape.outstanding_ranges,
            }),
        );
        self
    }

    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn with_measurements(mut self, measurements: serde_json::Value) -> Self {
        self.measurements = measurements;
        self
    }

    pub fn with_idle_baseline(mut self, baseline: serde_json::Value) -> Self {
        self.idle_baseline = baseline;
        self
    }

    fn logical_read_bytes(&self) -> u64 {
        self.read.as_ref().map_or(0, |read| read.bytes)
            + self
                .phases
                .values()
                .map(|phase| phase["read"]["bytes"].as_u64().unwrap_or(0))
                .sum::<u64>()
    }

    /// Print a concise human-readable report.
    pub fn print_human(&self, cfg: &Config) {
        println!(
            "backend={} workload={} elapsed_s={:.3}",
            backend_name(),
            cfg.workload,
            self.elapsed.as_secs_f64(),
        );
        println!(
            "io_size={} inflight={} worker_threads={} global_queue_interval={} seed={} output={}",
            cfg.range_size(),
            cfg.inflight,
            cfg.worker_threads,
            cfg.global_queue_interval
                .map_or_else(|| "default".to_string(), |value| value.to_string()),
            cfg.seed,
            cfg.output,
        );

        if cfg.workload == Workload::ReadRecent {
            println!(
                "read_api=phases replay_pages_per_call={} dont_cache={} outstanding_ranges=4",
                cfg.batch, cfg.dont_cache
            );
        } else {
            println!(
                "read_api={} read_mode={} batch={} dont_cache={} calls_in_flight={} outstanding_ranges={}",
                cfg.read_api,
                if cfg.read_api == ReadApi::StartReadMany {
                    "pagereader".to_string()
                } else {
                    cfg.read_mode.to_string()
                },
                cfg.batch,
                cfg.dont_cache,
                cfg.read_call_depth(),
                cfg.outstanding_ranges().unwrap()
            );
        }
        if let Some(ring_size) = cfg.effective_ring_size() {
            println!("ring_size={ring_size}");
        }
        if let Some(file_size) = cfg.file_size {
            println!("file_size={file_size}");
        }
        println!(
            "root={} page_size={} layout={}",
            cfg.root.display(),
            cfg.range_size(),
            cfg.layout
        );
        if let Some(cache) = cfg.cache {
            println!("cache={cache}");
        }
        if cfg.workload.has_writes() {
            println!("write_shape={}", cfg.write_shape);
            if cfg.workload == Workload::WriteSync {
                println!("sync_method={}", cfg.sync_method);
            } else {
                println!("sync_every={}", cfg.sync_mode);
            }
        }

        if let Some(read) = &self.read {
            read.print("read");
        }
        if let Some(write) = &self.write {
            write.print("write");
        }
        println!("allocator={}", allocator_config());
        println!(
            "measurements={} idle_baseline={}",
            self.measurements, self.idle_baseline
        );
        println!(
            "logical_read_bytes={} final_file_size={}",
            self.logical_read_bytes(),
            self.final_file_size
        );
        for (name, phase) in &self.phases {
            println!("phase={name} {phase}");
        }
    }

    /// Print a single JSON object for downstream processing.
    pub fn print_json(&self, cfg: &Config) {
        let json = json!({
            "backend": backend_name(),
            "allocator": allocator_config(),
            "workload": cfg.workload.to_string(),
            "duration_seconds": (cfg.workload != Workload::ReadRecent).then(|| cfg.duration().as_secs()),
            "io_size": cfg.io_size,
            "page_size": cfg.range_size(),
            "layout": cfg.layout.to_string(),
            "read_api": (cfg.workload != Workload::ReadRecent).then(|| cfg.read_api.to_string()),
            "read_mode": (cfg.workload != Workload::ReadRecent && cfg.read_api != ReadApi::StartReadMany).then(|| cfg.read_mode.to_string()),
            "batch": cfg.batch,
            "dont_cache": cfg.dont_cache,
            "calls_in_flight": (cfg.workload != Workload::ReadRecent).then(|| cfg.read_call_depth()),
            "outstanding_ranges": cfg.outstanding_ranges(),
            "inflight": cfg.inflight,
            "worker_threads": cfg.worker_threads,
            "ring_size": cfg.effective_ring_size(),
            "global_queue_interval": cfg.global_queue_interval,
            "file_size": cfg.file_size,
            "root": cfg.root,
            "reuse_root": cfg.reuse_root,
            "cache": cfg.cache.map(|mode| mode.to_string()),
            "write_shape": cfg.workload.has_writes().then(|| cfg.write_shape.to_string()),
            "sync_every": (cfg.workload.has_writes() && cfg.workload != Workload::WriteSync)
                .then(|| cfg.sync_mode.to_string()),
            "sync_method": (cfg.workload == Workload::WriteSync)
                .then(|| cfg.sync_method.to_string()),
            "seed": cfg.seed,
            "elapsed_ns": self.elapsed.as_nanos() as u64,
            "read": self.read.as_ref().map(OperationReport::to_json),
            "write": self.write.as_ref().map(OperationReport::to_json),
            "logical_read_bytes": self.logical_read_bytes(),
            "final_file_size": self.final_file_size,
            "phases": self.phases,
            "measurements": self.measurements,
            "idle_baseline": self.idle_baseline,
            "device": cfg.device,
        });
        println!("{json}");
    }
}

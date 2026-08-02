//! CLI and configuration types.

use clap::{CommandFactory, Parser, ValueEnum, builder::Styles, error::ErrorKind, value_parser};
use std::{env, fmt, path::PathBuf, time::Duration};

const DEFAULT_IO_SIZE: usize = 4 * 1024;
const DEFAULT_MULTI_BLOB_IO_SIZE: usize = 1024 * 1024;
const DEFAULT_BLOBS: usize = 4;
/// Protocol participant bound; exact descriptor capacity can reject smaller groups.
const MAX_BLOBS: usize = 32;

/// Benchmark workload to execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Workload {
    /// Sequential reads over a fixed-size file.
    #[value(name = "read_seq")]
    ReadSeq,
    /// Uniform random reads over a fixed-size file.
    #[value(name = "read_rand")]
    ReadRand,
    /// Sequential non-overlapping overwrites over a fixed-size file.
    #[value(name = "write_seq")]
    WriteSeq,
    /// Uniform random in-place overwrites over a fixed-size file.
    #[value(name = "write_rand")]
    WriteRand,
    /// Monotonic append writes to a growing file.
    #[value(name = "write_append")]
    WriteAppend,
    /// Sequential durable positioned writes over a fixed-size file.
    #[value(name = "write_sync")]
    WriteSync,
    /// Atomic append writes to a growing file.
    #[value(name = "write_atomic_append")]
    WriteAtomicAppend,
    /// Durable grouped append writes to multiple ordinary blobs.
    #[value(name = "write_multi_blob_append")]
    WriteMultiBlobAppend,
    /// Atomic grouped append writes published through one batch.
    #[value(name = "write_atomic_batch_append")]
    WriteAtomicBatchAppend,
    /// One append writer plus many random readers of the visible prefix.
    #[value(name = "read_write_append")]
    ReadWriteAppend,
}

impl Workload {
    /// Whether the workload benchmarks writes.
    pub const fn has_writes(self) -> bool {
        matches!(
            self,
            Self::WriteSeq
                | Self::WriteRand
                | Self::WriteAppend
                | Self::WriteSync
                | Self::WriteAtomicAppend
                | Self::WriteMultiBlobAppend
                | Self::WriteAtomicBatchAppend
                | Self::ReadWriteAppend
        )
    }

    /// Whether the workload benchmarks reads.
    pub const fn has_reads(self) -> bool {
        matches!(self, Self::ReadSeq | Self::ReadRand | Self::ReadWriteAppend)
    }

    /// Whether one operation is a durable append across multiple blobs.
    pub const fn is_multi_blob_append(self) -> bool {
        matches!(
            self,
            Self::WriteMultiBlobAppend | Self::WriteAtomicBatchAppend
        )
    }

    /// Whether the workload opens blobs through the atomic storage capability.
    pub const fn is_atomic(self) -> bool {
        matches!(self, Self::WriteAtomicAppend | Self::WriteAtomicBatchAppend)
    }
}

/// Read cache preparation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CacheMode {
    /// Best-effort warming by touching the file before timing.
    #[value(name = "warm")]
    Warm,
    /// Best-effort eviction with `posix_fadvise(..., DONTNEED)` before timing.
    /// Only the first pass through the file is truly cold: subsequent passes
    /// read from cache. Use a large enough file or short enough duration that
    /// the timed phase does not complete a full pass.
    #[value(name = "cold")]
    Cold,
}

/// Write payload layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum WriteShape {
    /// Single contiguous buffer per write.
    #[value(name = "contiguous")]
    Contiguous,
    /// Four-buffer vectored write per operation.
    #[value(name = "vectored")]
    Vectored,
}

/// Durable write implementation for the `write_sync` workload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SyncMethod {
    /// Call `write_at`, then call `sync`.
    #[value(name = "write_then_sync")]
    WriteThenSync,
    /// Call `write_at` with `WriteOptions::SYNC`.
    #[value(name = "write_at_sync")]
    WriteAtSync,
}

/// Write durability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMode {
    /// Flush once at the end of the timed phase.
    End,
    /// Flush every `N` writes in each writer stream.
    Every(u64),
}

/// Output format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable multi-line report.
    #[value(name = "human")]
    Human,
    /// Single JSON object.
    #[value(name = "json")]
    Json,
}

macro_rules! display_value_enum {
    ($($ty:ty),+ $(,)?) => {$(
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    self.to_possible_value()
                        .expect("all variants have clap names")
                        .get_name(),
                )
            }
        }
    )+};
}

display_value_enum!(Workload, CacheMode, WriteShape, SyncMethod, OutputFormat);

impl fmt::Display for SyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::End => f.write_str("end"),
            Self::Every(count) => write!(f, "{count}"),
        }
    }
}

/// Parsed and validated benchmark configuration.
#[derive(Clone, Debug, Parser)]
#[command(
    name = "storage_bench",
    about = "Benchmark the runtime storage backend",
    after_help = "The storage backend is selected at build time.\n\
                  Build normally for Tokio storage, or with `--features iouring-storage` for io_uring storage.",
    styles = Styles::styled(),
)]
pub struct Config {
    /// Workload to execute.
    #[arg(long, value_enum)]
    pub workload: Workload,

    /// Timed run duration in seconds.
    #[arg(long, default_value_t = 30, value_parser = value_parser!(u64).range(1..))]
    duration: u64,

    /// Exact operations per worker stream. When set, the duration is ignored.
    #[arg(long, value_parser = value_parser!(u64).range(1..))]
    pub operations: Option<u64>,

    /// Read or write size in bytes. Accepts suffixes like 64K, 4M, or 1G.
    ///
    /// Defaults to 1 MiB for multi-blob journal appends and 4 KiB otherwise.
    #[arg(long, value_parser = parse_byte_size_usize)]
    io_size: Option<usize>,

    /// Blobs in each durable multi-blob append group.
    ///
    /// Defaults to 4 for multi-blob workloads and is invalid for other workloads.
    #[arg(long, value_parser = value_parser!(usize))]
    blobs: Option<usize>,

    /// Contiguous appends to each blob before the group's durability barrier.
    #[arg(long, value_parser = value_parser!(u64).range(1..))]
    appends_per_batch: Option<u64>,

    /// Run an ordinary four-blob baseline alongside each atomic batch operation.
    #[arg(long, default_value_t = false)]
    pub paired_baseline: bool,

    /// Parallel worker count for steady-state workloads.
    #[arg(long, default_value_t = 1, value_parser = value_parser!(usize))]
    pub inflight: usize,

    /// Tokio worker thread count for the benchmark runtime.
    #[arg(
        long,
        default_value_t = default_worker_threads(),
        value_parser = value_parser!(usize)
    )]
    pub worker_threads: usize,

    /// Tokio scheduler ticks between global queue polls.
    #[arg(long, value_parser = value_parser!(u32))]
    pub global_queue_interval: Option<u32>,

    /// Initial fixed-size file length. Accepts suffixes like 64K, 4M, or 1G.
    #[arg(long, value_parser = parse_byte_size)]
    pub file_size: Option<u64>,

    /// Existing parent directory under which a unique benchmark directory is created.
    #[arg(long, default_value_os_t = default_root())]
    pub root: PathBuf,

    /// Best-effort cache preparation for read-heavy workloads.
    #[arg(long, value_enum)]
    pub cache: Option<CacheMode>,

    /// Write payload layout for write-heavy workloads.
    #[arg(long, value_enum, default_value = "contiguous")]
    pub write_shape: WriteShape,

    /// Request best-effort page-cache bypass for ordinary append writes.
    #[arg(long, default_value_t = false)]
    pub dont_cache: bool,

    /// Durable write method for the write_sync workload.
    #[arg(long, value_enum, default_value = "write_then_sync")]
    pub sync_method: SyncMethod,

    /// Durability cadence: `end` or a positive integer per writer stream.
    #[arg(long = "sync-every", default_value = "end", value_parser = parse_sync_mode)]
    pub sync_mode: SyncMode,

    /// Deterministic seed for payloads and random offsets.
    #[arg(long, default_value_t = 0)]
    pub seed: u64,

    /// Report format.
    #[arg(long, value_enum, default_value = "human")]
    pub output: OutputFormat,
}

impl Config {
    /// Parse CLI arguments and validate cross-field constraints.
    ///
    /// On parse or validation failure the error is printed directly (with
    /// proper formatting and color) and the process exits, matching clap's
    /// default behavior.
    pub fn parse() -> Self {
        // Filter out `--bench` which cargo passes to harness-less bench targets.
        let args = std::env::args_os().filter(|a| a != "--bench");
        let cfg = <Self as Parser>::try_parse_from(args).unwrap_or_else(|err| err.exit());
        if let Err(msg) = cfg.validate() {
            Self::command()
                .error(ErrorKind::ValueValidation, msg)
                .exit();
        }
        cfg
    }

    /// Timed run duration.
    pub const fn duration(&self) -> Duration {
        Duration::from_secs(self.duration)
    }

    /// Initial file size (panics if not set; only call after validation).
    pub const fn file_size(&self) -> u64 {
        self.file_size
            .expect("validated configuration must include --file-size")
    }

    /// Resolved I/O size after applying the workload-specific default.
    pub const fn io_size(&self) -> usize {
        match self.io_size {
            Some(io_size) => io_size,
            None if self.workload.is_multi_blob_append() => DEFAULT_MULTI_BLOB_IO_SIZE,
            None => DEFAULT_IO_SIZE,
        }
    }

    /// Resolved participant count for a validated multi-blob workload.
    pub const fn blobs(&self) -> usize {
        match self.blobs {
            Some(blobs) => blobs,
            None => DEFAULT_BLOBS,
        }
    }

    /// Resolved number of contiguous appends in one durable multi-blob operation.
    pub const fn appends_per_batch(&self) -> u64 {
        match self.appends_per_batch {
            Some(appends) => appends,
            None => 1,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.inflight == 0 {
            return Err("--inflight must be greater than zero".into());
        }
        if self.worker_threads == 0 {
            return Err("--worker-threads must be greater than zero".into());
        }
        if self.global_queue_interval == Some(0) {
            return Err("--global-queue-interval must be greater than zero".into());
        }
        if self.blobs == Some(0) {
            return Err("--blobs must be greater than zero".into());
        }
        if self.paired_baseline && self.workload != Workload::WriteAtomicBatchAppend {
            return Err("--paired-baseline is only valid for write_atomic_batch_append".into());
        }
        if !self.workload.is_multi_blob_append() && self.blobs.is_some() {
            return Err(
                "--blobs is only valid for write_multi_blob_append or write_atomic_batch_append"
                    .into(),
            );
        }
        if !self.workload.is_multi_blob_append() && self.appends_per_batch.is_some() {
            return Err("--appends-per-batch is only valid for multi-blob append workloads".into());
        }
        if self.blobs.is_some_and(|blobs| blobs > MAX_BLOBS) {
            return Err(format!("--blobs must not exceed {MAX_BLOBS}"));
        }
        if self.paired_baseline && self.blobs() != DEFAULT_BLOBS {
            return Err(format!(
                "--paired-baseline requires exactly {DEFAULT_BLOBS} blobs"
            ));
        }
        if self.workload.is_multi_blob_append() {
            let io_size = u64::try_from(self.io_size())
                .map_err(|_| "--io-size is too large for group byte accounting")?;
            let blobs = u64::try_from(self.blobs())
                .map_err(|_| "--blobs is too large for group byte accounting")?;
            io_size
                .checked_mul(blobs)
                .and_then(|bytes| bytes.checked_mul(self.appends_per_batch()))
                .ok_or_else(|| {
                    "--blobs * --io-size * --appends-per-batch exceeds u64".to_string()
                })?;
            if self.write_shape != WriteShape::Contiguous {
                return Err("multi-blob append workloads require --write-shape contiguous".into());
            }
            if self.sync_mode != SyncMode::End {
                return Err(
                    "--sync-every is not used by durable multi-blob append workloads".into(),
                );
            }
        }

        match self.workload {
            Workload::WriteAppend
            | Workload::WriteAtomicAppend
            | Workload::WriteMultiBlobAppend
            | Workload::WriteAtomicBatchAppend => {
                if self.file_size.is_some() {
                    return Err("--file-size is not used by append workloads".into());
                }
                if self.inflight != 1 {
                    return Err("append workloads only support --inflight 1".into());
                }
                if self.cache.is_some() {
                    return Err("--cache is only valid for read-heavy workloads".into());
                }
            }
            _ => {
                let file_size = self
                    .file_size
                    .ok_or_else(|| "--file-size is required for this workload".to_string())?;
                let io_size = self.io_size() as u64;
                if file_size < io_size {
                    return Err("--file-size must be at least --io-size".into());
                }
                if !file_size.is_multiple_of(io_size) {
                    return Err("--file-size must be a multiple of --io-size".into());
                }
                if matches!(
                    self.workload,
                    Workload::WriteSeq | Workload::WriteRand | Workload::WriteSync
                ) {
                    let total_blocks = file_size / io_size;
                    if total_blocks < self.inflight as u64 {
                        return Err(
                            "fixed-size write workloads require at least one block per worker"
                                .into(),
                        );
                    }
                    if self.workload == Workload::WriteSync
                        && !total_blocks.is_multiple_of(self.inflight as u64)
                    {
                        return Err(
                            "write_sync requires --file-size / --io-size to be divisible by --inflight"
                                .into(),
                        );
                    }
                }
            }
        }

        if self.workload.has_reads() {
            if self.cache.is_none() {
                return Err("--cache is required for read-heavy workloads".into());
            }
        } else if self.cache.is_some() {
            return Err("--cache is only valid for read-heavy workloads".into());
        }
        if matches!(self.cache, Some(CacheMode::Cold)) && !cfg!(target_os = "linux") {
            return Err("--cache cold is only supported on Linux".into());
        }

        if !self.workload.has_writes() {
            if self.write_shape != WriteShape::Contiguous {
                return Err("--write-shape is only valid for write-heavy workloads".into());
            }
            if self.sync_method != SyncMethod::WriteThenSync {
                return Err("--sync-method is only valid for write_sync".into());
            }
            if self.sync_mode != SyncMode::End {
                return Err("--sync-every is only valid for write-heavy workloads".into());
            }
            if self.dont_cache {
                return Err("--dont-cache is only valid for append workloads".into());
            }
        } else if self.workload == Workload::WriteSync && self.sync_mode != SyncMode::End {
            return Err("--sync-every is not used by write_sync".into());
        }
        if self.dont_cache && self.workload != Workload::WriteAppend {
            return Err("--dont-cache is only valid for write_append".into());
        }
        if self.workload != Workload::WriteSync && self.sync_method != SyncMethod::WriteThenSync {
            return Err("--sync-method is only valid for write_sync".into());
        }

        Ok(())
    }
}

fn default_worker_threads() -> usize {
    commonware_runtime::tokio::Config::default().worker_threads()
}

fn default_root() -> PathBuf {
    env::temp_dir()
}

fn parse_sync_mode(value: &str) -> Result<SyncMode, String> {
    if value == "end" {
        return Ok(SyncMode::End);
    }
    let count = value
        .parse::<u64>()
        .map_err(|err| format!("invalid value for --sync-every: {err}"))?;
    if count == 0 {
        return Err("--sync-every must be `end` or a positive integer".into());
    }
    Ok(SyncMode::Every(count))
}

fn parse_byte_size_usize(value: &str) -> Result<usize, String> {
    let bytes = parse_byte_size(value)?;
    usize::try_from(bytes).map_err(|_| format!("value is too large for this platform: {value}"))
}

/// Supported suffixes use binary multiples: `K`, `M`, `G`, `T`, `KB`, `MB`,
/// `GB`, `TB`, and the explicit `KiB`, `MiB`, `GiB`, `TiB` forms.
fn parse_byte_size(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("size value cannot be empty".into());
    }

    let split = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '_'))
        .unwrap_or(trimmed.len());
    let (number_part, suffix_part) = trimmed.split_at(split);
    if number_part.is_empty() {
        return Err(format!("invalid size value: {value}"));
    }

    let number = number_part.replace('_', "");
    let number = number
        .parse::<u64>()
        .map_err(|err| format!("invalid size value `{value}`: {err}"))?;

    let multiplier = match suffix_part.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024_u64.pow(2),
        "G" | "GB" | "GIB" => 1024_u64.pow(3),
        "T" | "TB" | "TIB" => 1024_u64.pow(4),
        suffix => {
            return Err(format!(
                "invalid size suffix `{suffix}` in `{value}`; expected K, M, G, T, KB, MB, GB, TB, KiB, MiB, GiB, or TiB"
            ));
        }
    };

    let result = number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size value is too large: {value}"))?;
    if result == 0 {
        return Err("size value must be greater than zero".into());
    }
    Ok(result)
}

#[cfg(test)]
#[allow(dead_code, unused_imports)]
mod tests {
    use super::*;

    fn multi_blob_config(workload: &str, blobs: &str) -> Config {
        Config::try_parse_from([
            "storage_bench",
            "--workload",
            workload,
            "--blobs",
            blobs,
            "--operations",
            "1",
        ])
        .unwrap()
    }

    #[test]
    fn multi_blob_count_is_bounded_before_allocation() {
        for workload in ["write_multi_blob_append", "write_atomic_batch_append"] {
            assert!(multi_blob_config(workload, "32").validate().is_ok());
            assert_eq!(
                multi_blob_config(workload, "33").validate(),
                Err("--blobs must not exceed 32".into())
            );
        }
    }

    #[test]
    fn paired_baseline_is_only_valid_for_four_blob_atomic_batches() {
        let paired = |workload, blobs| {
            Config::try_parse_from([
                "storage_bench",
                "--workload",
                workload,
                "--blobs",
                blobs,
                "--paired-baseline",
                "--operations",
                "1",
            ])
            .unwrap()
            .validate()
        };

        assert!(paired("write_atomic_batch_append", "4").is_ok());
        assert_eq!(
            paired("write_atomic_batch_append", "3"),
            Err("--paired-baseline requires exactly 4 blobs".into())
        );
        assert_eq!(
            paired("write_multi_blob_append", "4"),
            Err("--paired-baseline is only valid for write_atomic_batch_append".into())
        );
    }

    #[test]
    fn appends_per_batch_is_scoped_to_multi_blob_workloads() {
        let multi = Config::try_parse_from([
            "storage_bench",
            "--workload",
            "write_atomic_batch_append",
            "--appends-per-batch",
            "16",
            "--operations",
            "1",
        ])
        .unwrap();
        assert!(multi.validate().is_ok());
        assert_eq!(multi.appends_per_batch(), 16);

        let single = Config::try_parse_from([
            "storage_bench",
            "--workload",
            "write_append",
            "--appends-per-batch",
            "16",
            "--operations",
            "1",
        ])
        .unwrap();
        assert_eq!(
            single.validate(),
            Err("--appends-per-batch is only valid for multi-blob append workloads".into())
        );
    }
}

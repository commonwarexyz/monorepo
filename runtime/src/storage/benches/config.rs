//! CLI and configuration types.

use clap::{builder::Styles, error::ErrorKind, value_parser, CommandFactory, Parser, ValueEnum};
use std::{env, fmt, path::PathBuf, time::Duration};

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
    /// Durable positioned writes over a fixed-size file.
    #[value(name = "write_sync")]
    WriteSync,
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
                | Self::ReadWriteAppend
        )
    }

    /// Whether the workload benchmarks reads.
    pub const fn has_reads(self) -> bool {
        matches!(self, Self::ReadSeq | Self::ReadRand | Self::ReadWriteAppend)
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
    /// Call `write_at_sync`.
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

    /// Read or write size in bytes. Accepts suffixes like 64K, 4M, or 1G.
    #[arg(long, default_value = "4096", value_parser = parse_byte_size_usize)]
    pub io_size: usize,

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

        match self.workload {
            Workload::WriteAppend => {
                if self.file_size.is_some() {
                    return Err("--file-size is not used by write_append".into());
                }
                if self.inflight != 1 {
                    return Err("write_append only supports --inflight 1".into());
                }
                if self.cache.is_some() {
                    return Err("--cache is only valid for read-heavy workloads".into());
                }
            }
            _ => {
                let file_size = self
                    .file_size
                    .ok_or_else(|| "--file-size is required for this workload".to_string())?;
                let io_size = self.io_size as u64;
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
                            "write_seq, write_rand, and write_sync require at least one non-overlapping block per worker"
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
        } else if self.workload != Workload::WriteSync {
            if self.sync_method != SyncMethod::WriteThenSync {
                return Err("--sync-method is only valid for write_sync".into());
            }
        } else if self.sync_mode != SyncMode::End {
            return Err("--sync-every is not used by write_sync".into());
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
            ))
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

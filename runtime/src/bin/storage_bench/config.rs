//! CLI and configuration types.

use clap::{builder::Styles, error::ErrorKind, value_parser, CommandFactory, Parser, ValueEnum};
use std::{fmt, path::PathBuf, time::Duration};

/// Default logical I/O size used when the CLI does not override it.
pub(crate) const DEFAULT_IO_SIZE: usize = 4 * 1024;

/// Benchmark scenario to execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Scenario {
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
    /// One append writer plus many random readers of the visible prefix.
    #[value(name = "read_write_append")]
    ReadWriteAppend,
}

impl Scenario {
    /// Whether the scenario benchmarks writes.
    pub(crate) const fn has_writes(self) -> bool {
        matches!(
            self,
            Self::WriteSeq | Self::WriteRand | Self::WriteAppend | Self::ReadWriteAppend
        )
    }

    /// Whether the scenario benchmarks reads.
    pub(crate) const fn has_reads(self) -> bool {
        matches!(self, Self::ReadSeq | Self::ReadRand | Self::ReadWriteAppend)
    }
}

/// Read cache preparation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CacheMode {
    /// Best-effort warming by touching the file before timing.
    #[value(name = "warm")]
    Warm,
    /// Best-effort eviction with `posix_fadvise(..., DONTNEED)` before timing.
    #[value(name = "cold")]
    Cold,
}

/// Write payload layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum WriteShape {
    /// Single contiguous buffer per write.
    #[value(name = "contiguous")]
    Contiguous,
    /// Four-buffer vectored write per operation.
    #[value(name = "vectored")]
    Vectored,
}

/// Write durability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyncMode {
    /// Flush once at the end of the timed phase.
    End,
    /// Flush every `N` writes in each writer stream.
    Every(u64),
}

impl SyncMode {}

/// Output format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
    /// Human-readable multi-line report.
    #[value(name = "human")]
    Human,
    /// Single JSON object.
    #[value(name = "json")]
    Json,
}

#[derive(Clone, Debug, Parser)]
#[command(
    name = "storage_bench",
    about = "Benchmark the runtime storage backend",
    after_help = "The storage backend is selected at build time.\n\
                  Build normally for Tokio storage, or with `--features iouring-storage` for io_uring storage.",
    styles = clap_styles()
)]
struct Cli {
    /// Scenario to execute.
    #[arg(long, value_enum)]
    scenario: Scenario,

    /// Timed run duration in seconds.
    #[arg(long, default_value_t = 30, value_parser = value_parser!(u64))]
    duration: u64,

    /// Read or write size in bytes. Accepts suffixes like 64K, 4M, or 1G.
    #[arg(long, default_value = "4096", value_parser = parse_byte_size_usize)]
    io_size: usize,

    /// Parallel worker count for steady-state scenarios.
    #[arg(long, default_value_t = 1, value_parser = value_parser!(usize))]
    inflight: usize,

    /// Tokio worker thread count for the benchmark runtime.
    #[arg(
        long,
        default_value_t = default_runtime_worker_threads(),
        value_parser = value_parser!(usize)
    )]
    worker_threads: usize,

    /// Tokio scheduler ticks between global queue polls.
    #[arg(long, value_parser = value_parser!(u32))]
    global_queue_interval: Option<u32>,

    /// Initial fixed-size file length. Accepts suffixes like 64K, 4M, or 1G.
    #[arg(long, value_parser = parse_byte_size_u64)]
    file_size: Option<u64>,

    /// Parent directory under which a unique benchmark directory is created.
    #[arg(long, default_value = "/tmp")]
    root: PathBuf,

    /// Best-effort cache preparation for read-heavy scenarios.
    #[arg(long, value_enum)]
    cache: Option<CacheMode>,

    /// Write payload layout for write-heavy scenarios.
    #[arg(long, value_enum, default_value = "contiguous")]
    write_shape: WriteShape,

    /// Durability cadence: `end` or a positive integer per writer stream.
    #[arg(long = "sync-every", default_value = "end", value_parser = parse_sync_mode)]
    sync_mode: SyncMode,

    /// Deterministic seed for payloads and random offsets.
    #[arg(long, default_value_t = 0)]
    seed: u64,

    /// Report format.
    #[arg(long, value_enum, default_value = "human")]
    output: OutputFormat,
}

/// Parsed and validated benchmark configuration.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// Scenario to run.
    pub(crate) scenario: Scenario,
    /// Time budget for the workload phase.
    pub(crate) duration: Duration,
    /// Per-operation read or write size.
    pub(crate) io_size: usize,
    /// Number of concurrent workers for steady-state scenarios.
    pub(crate) inflight: usize,
    /// Tokio worker thread count used by the benchmark runtime.
    pub(crate) worker_threads: usize,
    /// Tokio global queue polling interval, when overridden.
    pub(crate) global_queue_interval: Option<u32>,
    /// Initial fixed-size file length, when the scenario needs one.
    pub(crate) file_size: Option<u64>,
    /// Parent directory used for creating a unique benchmark directory.
    pub(crate) root: PathBuf,
    /// Best-effort cache preparation for read-heavy scenarios.
    pub(crate) cache: Option<CacheMode>,
    /// Shape of writes issued by write-capable scenarios.
    pub(crate) write_shape: WriteShape,
    /// Durability policy for write-capable scenarios.
    pub(crate) sync_mode: SyncMode,
    /// Deterministic seed for payloads and random offsets.
    pub(crate) seed: u64,
    /// Final report format.
    pub(crate) output: OutputFormat,
}

impl Config {
    pub(crate) fn parse_or_exit() -> Self {
        Self::try_parse_from(std::env::args_os()).unwrap_or_else(|err| err.exit())
    }

    pub(crate) fn try_parse_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let cli = Cli::try_parse_from(args)?;
        let cfg = Self {
            scenario: cli.scenario,
            duration: Duration::from_secs(cli.duration),
            io_size: cli.io_size,
            inflight: cli.inflight,
            worker_threads: cli.worker_threads,
            global_queue_interval: cli.global_queue_interval,
            file_size: cli.file_size,
            root: cli.root,
            cache: cli.cache,
            write_shape: cli.write_shape,
            sync_mode: cli.sync_mode,
            seed: cli.seed,
            output: cli.output,
        };
        cfg.validate()
            .map_err(|message| Cli::command().error(ErrorKind::ValueValidation, message))?;
        Ok(cfg)
    }

    pub(crate) const fn file_size(&self) -> u64 {
        self.file_size
            .expect("validated configuration must include --file-size")
    }

    fn validate(&self) -> Result<(), String> {
        if self.duration.is_zero() {
            return Err("--duration must be greater than zero".into());
        }
        if self.io_size == 0 {
            return Err("--io-size must be greater than zero".into());
        }
        if self.inflight == 0 {
            return Err("--inflight must be greater than zero".into());
        }
        if self.worker_threads == 0 {
            return Err("--worker-threads must be greater than zero".into());
        }
        if self.global_queue_interval == Some(0) {
            return Err("--global-queue-interval must be greater than zero".into());
        }

        match self.scenario {
            Scenario::WriteAppend => {
                if self.file_size.is_some() {
                    return Err("--file-size is not used by write_append".into());
                }
                if self.inflight != 1 {
                    return Err("write_append only supports --inflight 1".into());
                }
                if self.cache.is_some() {
                    return Err("--cache is only valid for read-heavy scenarios".into());
                }
            }
            Scenario::ReadSeq
            | Scenario::ReadRand
            | Scenario::WriteSeq
            | Scenario::WriteRand
            | Scenario::ReadWriteAppend => {
                let file_size = self
                    .file_size
                    .ok_or_else(|| "--file-size is required for this scenario".to_string())?;
                let io_size = self.io_size as u64;
                if file_size < io_size {
                    return Err("--file-size must be at least --io-size".into());
                }
                if !file_size.is_multiple_of(io_size) {
                    return Err("--file-size must be a multiple of --io-size".into());
                }
            }
        }

        match self.scenario {
            Scenario::WriteSeq | Scenario::WriteRand => {
                let total_blocks = self.file_size() / self.io_size as u64;
                if total_blocks < self.inflight as u64 {
                    return Err(
                        "write_seq and write_rand require at least one non-overlapping block per worker"
                            .into(),
                    );
                }
            }
            Scenario::ReadWriteAppend => {}
            _ => {}
        }

        if self.scenario.has_reads() {
            if self.cache.is_none() {
                return Err("--cache is required for read-heavy scenarios".into());
            }
        } else if self.cache.is_some() {
            return Err("--cache is only valid for read-heavy scenarios".into());
        }

        if !self.scenario.has_writes() {
            if self.write_shape != WriteShape::Contiguous {
                return Err("--write-shape is only valid for write-heavy scenarios".into());
            }
            if self.sync_mode != SyncMode::End {
                return Err("--sync-every is only valid for write-heavy scenarios".into());
            }
        }

        Ok(())
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_value_enum(self, f)
    }
}

impl fmt::Display for CacheMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_value_enum(self, f)
    }
}

impl fmt::Display for WriteShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_value_enum(self, f)
    }
}

impl fmt::Display for SyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::End => f.write_str("end"),
            Self::Every(count) => write!(f, "{count}"),
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_value_enum(self, f)
    }
}

const fn clap_styles() -> Styles {
    Styles::styled()
}

fn fmt_value_enum<T: ValueEnum>(value: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let possible = value
        .to_possible_value()
        .expect("storage_bench value enums always have a canonical clap name");
    f.write_str(possible.get_name())
}

fn default_runtime_worker_threads() -> usize {
    commonware_runtime::tokio::Config::default().worker_threads()
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

fn parse_byte_size_u64(value: &str) -> Result<u64, String> {
    parse_byte_size(value)
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

    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size value is too large: {value}"))
}

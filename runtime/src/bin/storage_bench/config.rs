//! CLI and configuration types for `storage_bench`.

use crate::environment::{detected_backend, Backend};
use clap::{
    builder::{Styles, ValueParser},
    error::ErrorKind,
    value_parser, Arg, ColorChoice, Command, Error as ClapError,
};
use std::{fmt, io, path::PathBuf, time::Duration};

/// Default logical I/O size used when the CLI does not override it.
pub(crate) const DEFAULT_IO_SIZE: usize = 4 * 1024;

/// Benchmark scenario to execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scenario {
    /// Sequential reads over a fixed-size file.
    ReadSeq,
    /// Uniform random reads over a fixed-size file.
    ReadRand,
    /// Sequential non-overlapping overwrites over a fixed-size file.
    WriteSeq,
    /// Uniform random in-place overwrites over a fixed-size file.
    WriteRand,
    /// Monotonic append writes to a growing file.
    WriteAppend,
    /// One append writer plus many random readers of the visible prefix.
    ReadWriteAppend,
}

impl Scenario {
    /// Stable scenario name used in CLI and output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ReadSeq => "read_seq",
            Self::ReadRand => "read_rand",
            Self::WriteSeq => "write_seq",
            Self::WriteRand => "write_rand",
            Self::WriteAppend => "write_append",
            Self::ReadWriteAppend => "read_write_append",
        }
    }

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheMode {
    /// Best-effort warming by touching the file before timing.
    Warm,
    /// Best-effort eviction with `posix_fadvise(..., DONTNEED)` before timing.
    Cold,
}

impl CacheMode {
    /// Stable cache-mode name used in CLI and output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Cold => "cold",
        }
    }
}

/// Write payload layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteShape {
    /// Single contiguous buffer per write.
    Contiguous,
    /// Four-buffer vectored write per operation.
    Vectored,
}

impl WriteShape {
    /// Stable shape name used in CLI and output.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Contiguous => "contiguous",
            Self::Vectored => "vectored",
        }
    }
}

/// Write durability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyncMode {
    /// Flush once at the end of the timed phase.
    End,
    /// Flush every `N` writes in each writer stream.
    Every(u64),
}

impl SyncMode {
    /// Stable representation used in CLI and output.
    pub(crate) fn name(self) -> String {
        match self {
            Self::End => "end".to_string(),
            Self::Every(count) => count.to_string(),
        }
    }

    /// Parse the CLI representation of the sync cadence.
    fn parse(value: &str) -> Result<Self, String> {
        if value == "end" {
            return Ok(Self::End);
        }

        let count = value
            .parse::<u64>()
            .map_err(|err| format!("invalid value for --sync-every: {err}"))?;
        if count == 0 {
            return Err("--sync-every must be `end` or a positive integer".into());
        }
        Ok(Self::Every(count))
    }
}

/// Output format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputFormat {
    /// Human-readable multi-line report.
    Human,
    /// Single JSON object.
    Json,
}

/// Parsed and validated benchmark configuration.
#[derive(Clone, Debug)]
pub(crate) struct Config {
    /// Storage backend compiled into this benchmark binary.
    pub(crate) backend: Backend,
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

/// CLI parse failure or informational early exit.
#[derive(Debug)]
pub(crate) enum ParseError {
    /// Structured clap error, preserving styles and output stream.
    Clap(ClapError),
    /// Validation or parsing error produced by the harness itself.
    Message(String),
}

impl ParseError {
    /// Whether this parse result should terminate successfully.
    pub(crate) fn should_exit_success(&self) -> bool {
        match self {
            Self::Clap(err) => matches!(
                err.kind(),
                ErrorKind::DisplayHelp
                    | ErrorKind::DisplayVersion
                    | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ),
            Self::Message(_) => false,
        }
    }

    /// Print this error using the appropriate output path.
    pub(crate) fn print(&self) -> io::Result<()> {
        match self {
            Self::Clap(err) => err.print(),
            Self::Message(message) => {
                eprintln!("{message}");
                Ok(())
            }
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clap(err) => write!(f, "{err}"),
            Self::Message(message) => f.write_str(message),
        }
    }
}

impl From<String> for ParseError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<ClapError> for ParseError {
    fn from(err: ClapError) -> Self {
        Self::Clap(err)
    }
}

impl Config {
    /// Parse CLI arguments and validate scenario-specific constraints.
    pub(crate) fn parse_from<I, T>(args: I) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = command()
            .try_get_matches_from(args)
            .map_err(ParseError::from)?;

        let scenario = parse_scenario(
            matches
                .get_one::<String>("scenario")
                .expect("required by clap"),
        )?;
        let duration_secs = *matches
            .get_one::<u64>("duration")
            .expect("defaulted by clap");
        let io_size = *matches
            .get_one::<usize>("io-size")
            .expect("defaulted by clap");
        let inflight = *matches
            .get_one::<usize>("inflight")
            .expect("defaulted by clap");
        let worker_threads = matches
            .get_one::<usize>("worker-threads")
            .copied()
            .unwrap_or_else(default_runtime_worker_threads);
        let global_queue_interval = matches.get_one::<u32>("global-queue-interval").copied();
        let file_size = matches.get_one::<u64>("file-size").copied();
        let root = matches
            .get_one::<PathBuf>("root")
            .expect("defaulted by clap")
            .clone();
        let cache = matches
            .get_one::<String>("cache")
            .map(|value| parse_cache_mode(value))
            .transpose()?;
        let write_shape = parse_write_shape(
            matches
                .get_one::<String>("write-shape")
                .expect("defaulted by clap"),
        )?;
        let sync_mode = SyncMode::parse(
            matches
                .get_one::<String>("sync-every")
                .expect("defaulted by clap"),
        )?;
        let seed = *matches.get_one::<u64>("seed").expect("defaulted by clap");
        let output = parse_output(
            matches
                .get_one::<String>("output")
                .expect("defaulted by clap"),
        )?;

        let cfg = Self {
            backend: detected_backend(),
            scenario,
            duration: Duration::from_secs(duration_secs),
            io_size,
            inflight,
            worker_threads,
            global_queue_interval,
            file_size,
            root,
            cache,
            write_shape,
            sync_mode,
            seed,
            output,
        };
        cfg.validate().map_err(ParseError::from)?;
        Ok(cfg)
    }

    /// Return the fixed file size for scenarios that require one.
    pub(crate) const fn file_size(&self) -> u64 {
        self.file_size
            .expect("validated configuration must include --file-size")
    }

    /// Validate scenario-specific constraints that clap cannot express cleanly.
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
            Scenario::ReadWriteAppend => {
                if self.inflight == 0 {
                    return Err("read_write_append requires at least one reader".into());
                }
            }
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

fn command() -> Command {
    Command::new("storage_bench")
        .color(ColorChoice::Auto)
        .styles(Styles::styled())
        .about("Benchmark the runtime-selected storage backend")
        .after_help(
            "The storage backend is selected at build time.\n\
             Build normally for Tokio storage, or with `--features iouring-storage` for io_uring storage.",
        )
        .arg(
            Arg::new("scenario")
                .long("scenario")
                .help("Scenario to execute")
                .required(true)
                .value_parser([
                    "read_seq",
                    "read_rand",
                    "write_seq",
                    "write_rand",
                    "write_append",
                    "read_write_append",
                ]),
        )
        .arg(
            Arg::new("duration")
                .long("duration")
                .help("Timed run duration in seconds")
                .default_value("30")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("io-size")
                .long("io-size")
                .help("Read or write size in bytes; accepts suffixes like 64K, 4M, or 1G")
                .default_value("4096")
                .value_parser(ValueParser::new(parse_byte_size_usize)),
        )
        .arg(
            Arg::new("inflight")
                .long("inflight")
                .help("Parallel worker count for steady-state scenarios")
                .default_value("1")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("worker-threads")
                .long("worker-threads")
                .help(
                    "Tokio worker thread count for the benchmark runtime; defaults to the runtime default",
                )
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("global-queue-interval")
                .long("global-queue-interval")
                .help(
                    "Tokio scheduler ticks between global queue polls; defaults to Tokio's normal behavior",
                )
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("file-size")
                .long("file-size")
                .help("Initial fixed-size file length; accepts suffixes like 64K, 4M, or 1G")
                .value_parser(ValueParser::new(parse_byte_size_u64)),
        )
        .arg(
            Arg::new("root")
                .long("root")
                .help("Parent directory under which a unique benchmark directory is created")
                .default_value("/tmp")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("cache")
                .long("cache")
                .help("Best-effort cache preparation for read-heavy scenarios")
                .value_parser(["warm", "cold"]),
        )
        .arg(
            Arg::new("write-shape")
                .long("write-shape")
                .help("Write payload layout for write-heavy scenarios")
                .default_value("contiguous")
                .value_parser(["contiguous", "vectored"]),
        )
        .arg(
            Arg::new("sync-every")
                .long("sync-every")
                .help("Durability cadence: `end` or a positive integer per writer stream")
                .default_value("end"),
        )
        .arg(
            Arg::new("seed")
                .long("seed")
                .help("Deterministic seed for payloads and random offsets")
                .default_value("0")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Report format")
                .default_value("human")
                .value_parser(["human", "json"]),
        )
}

/// Parse the scenario CLI value.
fn parse_scenario(value: &str) -> Result<Scenario, String> {
    match value {
        "read_seq" => Ok(Scenario::ReadSeq),
        "read_rand" => Ok(Scenario::ReadRand),
        "write_seq" => Ok(Scenario::WriteSeq),
        "write_rand" => Ok(Scenario::WriteRand),
        "write_append" => Ok(Scenario::WriteAppend),
        "read_write_append" => Ok(Scenario::ReadWriteAppend),
        _ => Err(format!("invalid scenario: {value}")),
    }
}

/// Parse the cache-mode CLI value.
fn parse_cache_mode(value: &str) -> Result<CacheMode, String> {
    match value {
        "warm" => Ok(CacheMode::Warm),
        "cold" => Ok(CacheMode::Cold),
        _ => Err(format!("invalid cache mode: {value}")),
    }
}

/// Parse the write-shape CLI value.
fn parse_write_shape(value: &str) -> Result<WriteShape, String> {
    match value {
        "contiguous" => Ok(WriteShape::Contiguous),
        "vectored" => Ok(WriteShape::Vectored),
        _ => Err(format!("invalid write shape: {value}")),
    }
}

/// Parse the report-format CLI value.
fn parse_output(value: &str) -> Result<OutputFormat, String> {
    match value {
        "human" => Ok(OutputFormat::Human),
        "json" => Ok(OutputFormat::Json),
        _ => Err(format!("invalid output format: {value}")),
    }
}

/// Return the runtime's default Tokio worker thread count.
fn default_runtime_worker_threads() -> usize {
    commonware_runtime::tokio::Config::default().worker_threads()
}

/// Parse a human-friendly byte string into `u64`.
fn parse_byte_size_u64(value: &str) -> Result<u64, String> {
    parse_byte_size(value)
}

/// Parse a human-friendly byte string into `usize`.
fn parse_byte_size_usize(value: &str) -> Result<usize, String> {
    let bytes = parse_byte_size(value)?;
    usize::try_from(bytes).map_err(|_| format!("value is too large for this platform: {value}"))
}

/// Parse a human-friendly byte string.
///
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
